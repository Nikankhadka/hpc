//NikanKhadka_2059784


/*2. Password cracking using multithreading (15% - 100 marks)
In this task, you will be asked to use the “crypt” library to decrypt a password using multithreading.
You will be provided with two programs. The first program called “EncryptSHA512.c” allows you to
encrypt a password. For this assessment, you will be required to decrypt a 4-character password
consisting of 2 capital letters, and 2 numbers. The format of the password should be
“LetterLetterNumberNumber.” For example, “HP93.” Once you have generated your password, this
should then be entered into your program to decrypt the password. The method of input for the
encrypted password is up to you. The second program is a skeleton code to crack the password on a
single thread without any multithreading syntax. Your task is to use the pthread or omp library to
split the workload over many threads and find the password. Once the password has been found,
the program should finish meaning not all combinations of 2 letters and 2 numbers should be
explored unless it’s ZZ99 AND the last thread happens to finish last.*/

/******************************************************************************

  Compile with: gcc CrackAZ99.c -lpthread -lcrypt -o CrackAZ99 

  Execute with: ./CrackAZ99 <numberofthreads>
                   where number_of_threads should be > 0
*******************************************************************************/


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


// Counter to track number of combination used to crack the password
int count = 0; 
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



// required due to lack of standard function in c
void substr(char *dest, char *src, int start, int length)
{
  memcpy(dest, src + start, length);
  *(dest + length) = '\0';
}

/**
 This function can break the type of password described above. 
 All attempted combinations will be shown, and when the password is successfully found, 
 a "#" symbol will be added to the beginning of the line. Keep in mind that displaying intermediate results is a resource-intensive task, 
 so performance tests for this program should exclude this by commenting out the print statements
*/

static void *crack(void *args)
{
  sem_wait(&sem);

  int s;

  s = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
  if (s != 0)
    handle_error_en(s, "pthread_setcancelstate");

// standard loop counter variables
  int x, y, z;   

 // The string utilized in encrypting the password must allow for the presence of a null terminator ("\0"). If the salt value has been altered, the number of characters allocated for this string should be adjusted accordingly
  char salt[7];  
  //The current arrangement of letters being evaluated. If the length of the encrypted password is increased, the number of characters allocated for this string should be modified accordingly.
  char plain[7]; 

  // pointer to store the encrypted passwords adress
  char *enc;     

 // convert the ASCII int into ASCII char value
  char ascii_to_char;

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
    // Cancel the thread execution when required password is found
    s = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (s != 0)
      handle_error_en(s, "pthread_setcancelstate");

    // wait then cancel the remaining threads
    printf("\nWaiting for five seconds to let the remaining threads cancel...\n");
    sleep(5);
  }

  sem_post(&sem);
}

// prepare the sliced/divided number of records to be processed by each thread
void prepareSliceList()
{
  int sliceList[Num_of_Threads];
  int remainder = loopCount % Num_of_Threads;

  void *res;
  int s;

  //  store the sliced number of records to be processed by each thread
  for (int i = 0; i < Num_of_Threads; i++)
  {
    sliceList[i] = loopCount / Num_of_Threads;
  }

  // update the sliced number of characters that each thread represents and process without leaving any character unchecked

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

    //check the WorkLoad of each thread used
    printf("\nStartList[%d] = %d `%c`\t\tEndList[%d] = %d `%c`", k, startList[k], (char)startList[k], k, endList[k], (char)endList[k]);
  }

  struct threadInfo threadDetails[Num_of_Threads];
  //fetch the thread data
  for (int l = 0; l < Num_of_Threads; l++)
  {
    threadDetails[l].limit = startList[l];
    threadDetails[l].Upperlimit = endList[l];
  }

  pthread_t thread_id[Num_of_Threads];

  sem_init(&sem, 0, 1);

  printf("\n\nCreating threads and process to check the matching hash...\n");

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

  printf("\nSemaphore destroyed...\n");

  sem_destroy(&sem);
}

int main(int argc, char *argv[])
{
    Num_of_Threads = strtol(argv[1], NULL, 10);

  prepareSliceList();

  printf("\n%d Solutions and possible combinations explored\n", count);
  return 0;
}
