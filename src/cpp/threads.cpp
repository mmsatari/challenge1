#include <cstdio>
#include <unistd.h>
#include <pthread.h>
#include <cstring>
#include <iostream>

#define SLEEP_RANGE 10

void *thread_func(void *arg) {
	auto thread_id = pthread_self();
	auto a_little = new int;
	*a_little = rand() % SLEEP_RANGE;

	/* Used `printf` to eliminate the need to use mutex */
	printf("Thread with id : %ld started\n", thread_id);
	sleep(*a_little);
	printf("Thread with id : %ld is exiting\n", thread_id);
	pthread_exit(a_little);
}

int main() {
	int err_code;
	int pool_size = 0;

	std::cout << "Please enter the number of threads to create: ";
	std::cin >> pool_size;

	pthread_t *threadpool = new pthread_t[pool_size];

	for (int i = 0; i < pool_size; i++) {
		if ((err_code = pthread_create(&threadpool[i], nullptr, thread_func, nullptr))) {
			std::cout << "Thread creation failed : " << strerror(err_code);
			exit(-1);
		}
	}

	for (int i = 0; i < pool_size; i++) {
		void *return_val = nullptr;
		if ((err_code = pthread_join(threadpool[i], &return_val))) {
			printf("Failed to join Thread : %s\n", strerror(err_code));
		} else if (return_val) {
			printf("Thread with Id : %ld exited and returned : %d\n", threadpool[i], *(int *) return_val);
			delete (int *) return_val;
		}
	}
	delete[] threadpool;
}