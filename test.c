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

#define QUEUE_DEPTH 1
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


void print_to_user(char *buf, int len){
    while (len > 0) {
        fputc(*buf++, stdout);
        len--;
    }
}


off_t file_size(int fd){
    struct stat st;

    if(fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }
        return st.st_size;
}


int init_io_uring(struct application_data* s){
    struct io_uring_params p;
    struct sq_ring* sqring = &s->sq_ring;
    struct cq_ring* cqring = &s->cq_ring;
    void *mapped_ptr;
    int sqring_sz, cqring_sz;


    memset(&p, 0, sizeof(p));
    s->ring_fd = io_uring_setup(QUEUE_DEPTH, &p);
    if (s->ring_fd < 0) {
        perror("io_uring_setup");
        return 1;
    }

    sqring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    cqring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);


    if (cqring_sz > sqring_sz) {
        sqring_sz = cqring_sz;
    }
    cqring_sz = sqring_sz;

    //map the rings
    mapped_ptr = mmap(0, sqring_sz, PROT_READ|PROT_WRITE, MAP_SHARED, s->ring_fd, IORING_OFF_SQ_RING);
    if (mapped_ptr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

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
    s->sqes = mmap(0, p.sq_entries*sizeof(struct io_uring_sqe), PROT_READ|PROT_WRITE, MAP_SHARED, s->ring_fd, IORING_OFF_SQES);
    if (s->sqes == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    return 0;
}

int submit_read_req(char* filename, struct application_data* s){
    struct request_info* req_info;
    int blocks;

    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0 ) {
        perror("open");
        return 1;
    }

    struct sq_ring* sqring = &s->sq_ring;
    unsigned index = 0, current_block = 0, tail = 0, next_tail = 0;

    off_t size = file_size(file_fd);
    if (size < 0)
        return 1;
    off_t bytes_remaining = size;
    blocks = (int) size / BLOCK_DIM;
    if(size % BLOCK_DIM) blocks++;

    req_info = malloc(sizeof(*req_info) + sizeof(struct iovec) * blocks);
    if(!req_info) {
        fprintf(stderr, "Unable to allocate memory\n");
        return 1;
    }
    req_info->file_size = size;

    //setup the iov for the vectored read
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

    //add the SQE at the tail of the ring buffer
    next_tail = tail = *sqring->tail;
    next_tail++;
    barrier();
    index = tail & *s->sq_ring.ring_mask;
    struct io_uring_sqe *sqe = &s->sqes[index];
    sqe->fd = file_fd;
    sqe->opcode = IORING_OP_READV;
    sqe->addr = (unsigned long) req_info->iovecs;
    sqe->flags = 0;
    sqe->len = blocks;
    sqe->off = 0;
    sqe->user_data = (unsigned long long) req_info;
    sqring->array[index] = index;
    tail = next_tail;

    //update the tail
    if(*sqring->tail != tail){
        *sqring->tail = tail;
        barrier();
    }

    //submit the request and wait for 1 completion
    int ret =  io_uring_enter(s->ring_fd, 1, 1, IORING_ENTER_GETEVENTS);
    if(ret < 0){
        perror("io_uring_enter");
        return 1;
    }

    return 0;
}


void read_from_cq(struct application_data *s){
    struct request_info* file_inf;
    struct cq_ring* cqring = &s->cq_ring;
    struct io_uring_cqe* cqe;
    unsigned head, reaped = 0;
    int blocks;

    head = *cqring->head;

    while(1){
        barrier();

        //checking if the ring is empty
        if (head == *cqring->tail)
            break;

        //getting the entry
        cqe = &cqring->cqes[head & *s->cq_ring.ring_mask];
        file_inf = (struct request_info*) cqe->user_data;
        if (cqe->res < 0){
            printf("error while reading, error number:%d",-cqe->res);
        }

        blocks = (int) (file_inf->file_size / BLOCK_DIM);
        if(file_inf->file_size % BLOCK_DIM) blocks++;

        for(int i=0; i<blocks; i++)
            print_to_user(file_inf->iovecs[i].iov_base, file_inf->iovecs[i].iov_len);

        head++;
    }

    *cqring->head = head;
    barrier();
}


int main(int argc, char *argv[]){
    struct application_data s;
    memset(&s, 0, sizeof(struct application_data));

    if(argc < 2) {
        printf("Need the filename as parameter\n");
        return 1;
    }

    if(init_io_uring(&s)) {
        printf("Error during setup\n");
        return 1;
    }

    if(submit_read_req(argv[1], &s)) {
        printf("Error reading file\n");
        return 1;
    }
    read_from_cq(&s);


    return 0;
}
