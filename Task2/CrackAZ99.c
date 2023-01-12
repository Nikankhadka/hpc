#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <crypt.h>
#include <unistd.h>
#include <semaphore.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>

#define handle_error_en(en, msg) \
  do                             \
  {                              \
    errno = en;                  \
    perror(msg);                 \
    exit(EXIT_FAILURE);          \
  } while (0)

/******************************************************************************
  Demonstrates how to crack an encrypted password using a simple
  "brute force" algorithm. Works on passwords that consist only of 2 uppercase
  letters and a 2 digit integer.

  Compile with:
    gcc CrackAZ99.c -lpthread -lcrypt -o CrackAZ99 

  Execute with:
    ./CrackAZ99 <numberofthreads>
    where number_of_threads should be > 0
*******************************************************************************/

int count = 0; // A counter used to track the number of combinations explored so far
int Num_of_Threads;
// int loopCount = 67600;
int loopCount = 26;
bool isFound = false;

struct threadInfo
{
  int limit;
  int Upperlimit;
};

char startChar, endChar;

char *salt_and_encrypted;

sem_t sem;

// Required by lack of standard function in C.
void substr(char *dest, char *src, int start, int length)
{
  memcpy(dest, src + start, length);
  *(dest + length) = '\0';
}

/**
 This function can crack the kind of password explained above. All combinations
 that are tried are displayed and when the password is found, #, is put at the 
 start of the line. Note that one of the most time consuming operations that 
 it performs is the output of intermediate results, so performance experiments 
 for this kind of program should not include this. i.e. comment out the printfs.
*/

static void *crack(void *args)
{
  sem_wait(&sem);

  int s;

  s = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
  if (s != 0)
    handle_error_en(s, "pthread_setcancelstate");

  int x, y, z;   // Loop counters
  char salt[7];  // String used in hashing the password. Need space for \0 // incase you have modified the salt value, then should modifiy the number accordingly
  char plain[7]; // The combination of letters currently being checked // Please modifiy the number when you enlarge the encrypted password.
  char *enc;     // Pointer to the encrypted password

  char ascii_to_char; // to convert the ASCII int into ASCII char value

  substr(salt, salt_and_encrypted, 0, 6);

  struct threadInfo *tI = (struct threadInfo *)args;
  int startLimit = tI->limit;
  int endLimit = tI->Upperlimit;

  if (!isFound)
  {
    char startingChar = startLimit;
    char endingChar = endLimit;
    printf("\nLooping through `%c` to `%c`\n", startingChar, endingChar);

    for (x = startLimit; x <= endLimit; x++)
    {
      ascii_to_char = x;
      for (y = 'A'; y <= 'Z'; y++)
      {
        for (z = 0; z <= 99; z++)
        {
          sprintf(plain, "%c%c%02d", ascii_to_char, y, z);
          enc = (char *)crypt(plain, salt);
          count++;
          if (strcmp(salt_and_encrypted, enc) == 0)
          {
            printf("\n\n#%-8d%s %s\n\n", count, plain, enc);

            isFound = true;
          
          }
        }
      }
    }
  }
  else
  {
    // cancel all other threads when the required password has been found
    s = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (s != 0)
      handle_error_en(s, "pthread_setcancelstate");

    // waiting for a second to let the thread cancel
    printf("\nWaiting for five seconds to let the remaining threads cancel...\n");
    sleep(5);
  }

  sem_post(&sem);
}

// preparing the slicelist
void prepareSliceList()
{
  int sliceList[Num_of_Threads];
  int remainder = loopCount % Num_of_Threads;

  void *res;
  int s;

  // to store the sliced/divided number of records to be processed by each thread
  for (int i = 0; i < Num_of_Threads; i++)
  {
    sliceList[i] = loopCount / Num_of_Threads;
  }

  // to update the sliced/divided number of characters that each thread
  // has to process without leaving any characters unprocessed/unchecked
  for (int j = 0; j < remainder; j++)
  {
    sliceList[j] = sliceList[j] + 1;
  }

  int startList[Num_of_Threads];
  int endList[Num_of_Threads];

  /*
  * dividing the work load to the thread
  *  */
  for (int k = 0; k < Num_of_Threads; k++)
  {
    if (k == 0)
    {
      startList[k] = 65; // ASCII value of 'A'
    }
    else
    {
      startList[k] = endList[k - 1] + 1;
    }

    endList[k] = startList[k] + sliceList[k] - 1;
    //checking the work load of each thread
    printf("\nstartList[%d] = %d `%c`\t\tendList[%d] = %d `%c`", k, startList[k], (char)startList[k], k, endList[k], (char)endList[k]);
  }

  struct threadInfo threadDetails[Num_of_Threads];
//greating thread data
  for (int l = 0; l < Num_of_Threads; l++)
  {
    threadDetails[l].limit = startList[l];
    threadDetails[l].Upperlimit = endList[l];
  }

  pthread_t thread_id[Num_of_Threads];

  sem_init(&sem, 0, 1);

  printf("\n\nCreating threads and checking for a matching hash...\n");

  // Copy and paste the ecrypted password here using EncryptShA512 program
  salt_and_encrypted = "$6$AS$a2lb05Cfr5T89rBnajIB0AXI79VSJfYrnEgB9l0iw0pz38j17/iPhXVPn029Pd8b32NzPD9TmeCl6ksksTNIi0";

  printf("Input salt_and_encrypted: %s\n", salt_and_encrypted);

  for (int m = 0; m < Num_of_Threads; m++)
  {
    s = pthread_create(&thread_id[m], NULL, &crack, &threadDetails[m]);
    if (s != 0)
      handle_error_en(s, "pthread_create");
  }

  for (int n = 0; n < Num_of_Threads; n++)
  {
    if (isFound)
    {
      // printf("\nThreadID: %d is canceling\n", n);

      s = pthread_cancel(thread_id[n]);
      if (s != 0)
        handle_error_en(s, "pthread_cancel");
    }

    s = pthread_join(thread_id[n], &res);

    if (s != 0)
      handle_error_en(s, "pthread_join");

    if (res == PTHREAD_CANCELED)
      printf("\nThreadID: %d was canceled...\n", n);
    else
      printf("\nThreadID: %d was not canceled...\n", n);
  }

  printf("\nsemaphore destroyed...\n");

  sem_destroy(&sem);
}

int main(int argc, char *argv[])
{
    Num_of_Threads = strtol(argv[1], NULL, 10);

  prepareSliceList();

  printf("\n%d solutions explored\n", count);
  return 0;
}
