#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <linux/io_uring.h>

#define QUEUE_DEPTH 64
#define BLOCK_DIM    1024

#define barrier() __asm__ __volatile__("mfence":::"memory")

struct sq_ring {
    unsigned *head;
    unsigned *tail;
    unsigned *ring_mask;
    unsigned *ring_entries;
    unsigned *flags;
    unsigned *array;
};

struct cq_ring {
    unsigned *head;
    unsigned *tail;
    unsigned *ring_mask;
    unsigned *ring_entries;
    struct io_uring_cqe *cqes;
};

struct application_data {
    int ring_fd;
    struct sq_ring sq_ring;
    struct io_uring_sqe *sqes;
    struct cq_ring cq_ring;
};

struct request_info {
    off_t file_size;
    struct iovec iovecs[]; 
};


int io_uring_setup(unsigned entries, struct io_uring_params *p){
    return (int) syscall(__NR_io_uring_setup, entries, p);
}

int io_uring_enter(int ring_fd, unsigned int to_submit,
                          unsigned int min_complete, unsigned int flags){
    return (int) syscall(__NR_io_uring_enter, ring_fd, to_submit, min_complete,
                   flags, NULL, 0);
}


/* Print the buffer to the console one character at the time */
void print_to_user(char *buf, int len){
    while (len > 0) {
        printf("%c",*buf);
        buf++;
        len--;
    }
    printf("\n");
}


off_t file_size(int fd){
    struct stat st;

    if(fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }
        return st.st_size;
}


int init_io_uring(struct application_data* ctx){
    struct io_uring_params p;
    struct sq_ring* sqring = &ctx->sq_ring;
    struct cq_ring* cqring = &ctx->cq_ring;
    void *mapped_ptr;
    int sqring_sz, cqring_sz;


    memset(&p, 0, sizeof(p));
    /*
     * Call io_uring_setup. It returns a file descriptor that we can use to map the queues
     * Pass also the io_uring_params struct, it will be filled with the offsets in which 
     * the different components of io_uring have been allocated
     */
    ctx->ring_fd = io_uring_setup(QUEUE_DEPTH, &p);
    if (ctx->ring_fd < 0) {
        perror("io_uring_setup");
        return 1;
    }

    sqring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);

    /*
     * Here we map the two rings into userspace. The memory has alrealdy been allocated by the kernel
     * during the io_uring_setup system call, we just need to map it to userspace.
     */
    mapped_ptr = mmap(0, sqring_sz, PROT_READ|PROT_WRITE, MAP_SHARED, ctx->ring_fd, IORING_OFF_SQ_RING);
    if (mapped_ptr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /*
     * proceed and save into our data structures the addresses of the different components 
     * according to the offsets provided by the kernel
     */
    sqring->head = mapped_ptr + p.sq_off.head;
    sqring->tail = mapped_ptr + p.sq_off.tail;
    sqring->ring_mask = mapped_ptr + p.sq_off.ring_mask;
    sqring->ring_entries = mapped_ptr + p.sq_off.ring_entries;
    sqring->flags = mapped_ptr + p.sq_off.flags;
    sqring->array = mapped_ptr + p.sq_off.array;

    cqring->head = mapped_ptr + p.cq_off.head;
    cqring->tail = mapped_ptr + p.cq_off.tail;
    cqring->ring_mask = mapped_ptr + p.cq_off.ring_mask;
    cqring->ring_entries = mapped_ptr + p.cq_off.ring_entries;
    cqring->cqes = mapped_ptr + p.cq_off.cqes;

    //map the sqe array
    ctx->sqes = mmap(0, p.sq_entries*sizeof(struct io_uring_sqe), PROT_READ|PROT_WRITE, MAP_SHARED, ctx->ring_fd, IORING_OFF_SQES);
    if (ctx->sqes == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    return 0;
}

int submit_read_req(char* filename, struct application_data* ctx){
    struct request_info* req_info;
    int blocks;
    struct sq_ring* sqring = &ctx->sq_ring;
    struct io_uring_sqe *sqe;
    unsigned index = 0;
    unsigned current_block = 0;
    unsigned tail = 0;

    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0 ) {
        perror("open");
        return 1;
    }

    off_t size = file_size(file_fd);
    if (size < 0)
        return 1;
    off_t bytes_remaining = size;
    blocks = (int) size / BLOCK_DIM;
    if(size % BLOCK_DIM) 
        blocks++;

    /* Allocate memory for the iovec structure to use in the readv request */
    req_info = malloc(sizeof(*req_info) + sizeof(struct iovec) * blocks);
    if(!req_info) {
        printf("Malloc failed\n");
        return 1;
    }
    req_info->file_size = size;

    /* Fill out the iovec for the readv request */
    while(bytes_remaining){
        off_t bytes_to_read = bytes_remaining;
        if (bytes_to_read > BLOCK_DIM)
            bytes_to_read = BLOCK_DIM;

        req_info->iovecs[current_block].iov_len = bytes_to_read;

        void *buf;
        if( posix_memalign(&buf, BLOCK_DIM, BLOCK_DIM)){
            perror("posix_memalign");
            return 1;
        }
        req_info->iovecs[current_block].iov_base = buf;

        current_block++;
        bytes_remaining -= bytes_to_read;
    }

    /* Fill out the request and insert it into the submission ring 
     * we need to use barriers to be sure that the all the writes are
     * done before we update the tail
     */
    tail = *sqring->tail;
    index = tail & *ctx->sq_ring.ring_mask;
    sqe = &ctx->sqes[index];
    sqe->fd = file_fd;
    sqe->opcode = IORING_OP_READV;
    sqe->addr = (unsigned long) req_info->iovecs;
    sqe->flags = IOSQE_IO_LINK;
    sqe->len = blocks;
    sqe->off = 0;
    sqe->user_data = (unsigned long long) req_info;
    sqring->array[index] = index;
    tail++;
    barrier();

    //update the tail
    if(*sqring->tail != tail){
        *sqring->tail = tail;
        barrier();
    }
    return 0;
}

void read_from_cq(struct application_data *s){
    struct request_info* file_inf;
    struct cq_ring* cqring = &s->cq_ring;
    struct io_uring_cqe* cqe;
    unsigned head, reaped = 0;
    int blocks;

    /* We use a local variable to keep track of the head, will update the one
       visible by the kernel at the end of the completion process */
    head = *cqring->head;

    /* Enter the loop and start consuming completion queue events (CQEs)
     * until the ring is empty */
    while(1){
        barrier();

        /* If the head and the tail are equal it means that the ring is empty, we can finish */
        if (head == *cqring->tail)
            break;

        /* Grab the next CQE */
        cqe = &cqring->cqes[head & *s->cq_ring.ring_mask];

        file_inf = (struct request_info*) cqe->user_data;
        /* check for errors */
        if (cqe->res < 0){
            printf("error while reading, error number:%d",-cqe->res);
        }

        blocks = (int) (file_inf->file_size / BLOCK_DIM);
        if(file_inf->file_size % BLOCK_DIM) 
            blocks++;

        /* The request is complete so the iovec will contain the contents of the file, print them */
        for(int i=0; i<blocks; i++)
            print_to_user(file_inf->iovecs[i].iov_base, file_inf->iovecs[i].iov_len);

        head++;
    }

    /* Make visible to the kernel that we have consumed the CQEs, 
       reminder that *cqring->head is the field placed in the shared memory */
    *cqring->head = head;
    barrier();
}


int main(int argc, char *argv[]){
    struct application_data ctx;
    memset(&ctx, 0, sizeof(struct application_data));

    if(argc < 2) {
        printf("Need the filename as parameter\n");
        return 1;
    }

    if(init_io_uring(&ctx) < 0) {
        printf("Error during setup\n");
        return 1;
    }

    /* For each argument passed, fill out a request and put it into the submission ring */
    for(int i=1; i<argc; i++){
        if(submit_read_req(argv[i], &ctx) < 0) {
            printf("Error reading file\n");
            return 1;
        }
    }

    /* Submit the request and wait for everything to be completed */
    int ret =  io_uring_enter(ctx.ring_fd, argc-1, argc-1, IORING_ENTER_GETEVENTS);
    if(ret < 0){
        perror("io_uring_enter");
        return 1;
    }

    /* Read all the completions and print the contents of the read files to  */
    read_from_cq(&ctx);


    return 0;
}
