# Meltdown and Spectre attack exploit

## Introduction

This report comprehensively examines Spectre and Meltdown vulnerabilities. Our goal is to dissect these vulnerabilities, offering a technical analysis of their underlying mechanisms. We will explore the "how" to understand the core principles and mechanisms facilitating these attacks. We will also investigate the "how to" by methodically deconstructing the techniques used for execution. Lastly, we will thoroughly examine "how to mitigate" these threats, explaining the strategies and defences in place to protect systems and valuable data.



## Requirements
> * Requires a machine that is susceptible to Meltdown & Spectre Attacks, prior to OS patch. A VM is provided ![here](https://seed.nyc3.cdn.digitaloceanspaces.com/SEEDUbuntu-16.04-32bit.zip)





### Reading Cache vs Memory 

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

1.
> Access time for array[0*4096]: 1632 CPU cycles
Access time for array[1*4096]: 346 CPU cycles
Access time for array[2*4096]: 348 CPU cycles
Access time for array[3*4096]: 60 CPU cycles
Access time for array[4*4096]: 340 CPU cycles
Access time for array[5*4096]: 336 CPU cycles
Access time for array[6*4096]: 530 CPU cycles
Access time for array[7*4096]: 62 CPU cycles
Access time for array[8*4096]: 336 CPU cycles
Access time for array[9*4096]: 346 CPU cycles

2.
> Access time for array[0*4096]: 1642 CPU cycles
Access time for array[1*4096]: 332 CPU cycles
Access time for array[2*4096]: 318 CPU cycles
Access time for array[3*4096]: 58 CPU cycles
Access time for array[4*4096]: 378 CPU cycles
Access time for array[5*4096]: 350 CPU cycles
Access time for array[6*4096]: 394 CPU cycles
Access time for array[7*4096]: 58 CPU cycles
Access time for array[8*4096]: 394 CPU cycles
Access time for array[9*4096]: 402 CPU cycles

3.
> Access time for array[0*4096]: 1540 CPU cycles
Access time for array[1*4096]: 408 CPU cycles
Access time for array[2*4096]: 372 CPU cycles
Access time for array[3*4096]: 52 CPU cycles
Access time for array[4*4096]: 378 CPU cycles
Access time for array[5*4096]: 1006 CPU cycles
Access time for array[6*4096]: 400 CPU cycles
Access time for array[7*4096]: 66 CPU cycles
Access time for array[8*4096]: 332 CPU cycles
Access time for array[9*4096]: 400 CPU cycles

4.
> Access time for array[0*4096]: 1522 CPU cycles
Access time for array[1*4096]: 404 CPU cycles
Access time for array[2*4096]: 394 CPU cycles
Access time for array[3*4096]: 60 CPU cycles
Access time for array[4*4096]: 410 CPU cycles
Access time for array[5*4096]: 398 CPU cycles
Access time for array[6*4096]: 354 CPU cycles
Access time for array[7*4096]: 62 CPU cycles
Access time for array[8*4096]: 360 CPU cycles
Access time for array[9*4096]: 336 CPU cycles

5.
> Access time for array[0*4096]: 1526 CPU cycles
Access time for array[1*4096]: 1274 CPU cycles
Access time for array[2*4096]: 402 CPU cycles
Access time for array[3*4096]: 64 CPU cycles
Access time for array[4*4096]: 392 CPU cycles
Access time for array[5*4096]: 396 CPU cycles
Access time for array[6*4096]: 408 CPU cycles
Access time for array[7*4096]: 58 CPU cycles
Access time for array[8*4096]: 330 CPU cycles
Access time for array[9*4096]: 324 CPU cycles

6.
> Access time for array[0*4096]: 1702 CPU cycles
Access time for array[1*4096]: 346 CPU cycles
Access time for array[2*4096]: 402 CPU cycles
Access time for array[3*4096]: 68 CPU cycles
Access time for array[4*4096]: 420 CPU cycles
Access time for array[5*4096]: 416 CPU cycles
Access time for array[6*4096]: 428 CPU cycles
Access time for array[7*4096]: 68 CPU cycles
Access time for array[8*4096]: 412 CPU cycles
Access time for array[9*4096]: 408 CPU cycles

7.
> Access time for array[0*4096]: 1648 CPU cycles
Access time for array[1*4096]: 342 CPU cycles
Access time for array[2*4096]: 336 CPU cycles
Access time for array[3*4096]: 82 CPU cycles
Access time for array[4*4096]: 358 CPU cycles
Access time for array[5*4096]: 542908 CPU cycles
Access time for array[6*4096]: 362 CPU cycles
Access time for array[7*4096]: 78 CPU cycles
Access time for array[8*4096]: 626 CPU cycles
Access time for array[9*4096]: 350 CPU cycles

8.
> Access time for array[0*4096]: 1560 CPU cycles
Access time for array[1*4096]: 328 CPU cycles
Access time for array[2*4096]: 382 CPU cycles
Access time for array[3*4096]: 52 CPU cycles
Access time for array[4*4096]: 400 CPU cycles
Access time for array[5*4096]: 390 CPU cycles
Access time for array[6*4096]: 390 CPU cycles
Access time for array[7*4096]: 68 CPU cycles
Access time for array[8*4096]: 392 CPU cycles
Access time for array[9*4096]: 386 CPU cycles

9.
> Access time for array[0*4096]: 1538 CPU cycles
Access time for array[1*4096]: 336 CPU cycles
Access time for array[2*4096]: 362 CPU cycles
Access time for array[3*4096]: 54 CPU cycles
Access time for array[4*4096]: 352 CPU cycles
Access time for array[5*4096]: 406 CPU cycles
Access time for array[6*4096]: 408 CPU cycles
Access time for array[7*4096]: 56 CPU cycles
Access time for array[8*4096]: 396 CPU cycles
Access time for array[9*4096]: 1248 CPU cycles

10.
> Access time for array[0*4096]: 1788 CPU cycles
Access time for array[1*4096]: 350 CPU cycles
Access time for array[2*4096]: 336 CPU cycles
Access time for array[3*4096]: 76 CPU cycles
Access time for array[4*4096]: 324 CPU cycles
Access time for array[5*4096]: 334 CPU cycles
Access time for array[6*4096]: 334 CPU cycles
Access time for array[7*4096]: 76 CPU cycles
Access time for array[8*4096]: 330 CPU cycles
Access time for array[9*4096]: 418 CPU cycles

# Meltdown Attack in C
Meltdown is a vulnerability that exploits the flaw inside the Intel CPUs, if the target machine is an AMD system, the attack will not work. 
























