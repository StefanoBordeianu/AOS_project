# AOS_project
io_uring demo for the part B of the Advanced Operating Systems course

It consists of a program that will read and print to console the files passed as input.
This program is meant as a way to show how the raw io_uring API works. 

It fills a request for each file then call io_uring_enter() to submit them to the kernel and wait for the completion of all the requests.
It then proceed to consume all the completions from the completion queue and print the content of the files 

program can be compiled with:
$ gcc read_file.c