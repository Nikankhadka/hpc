//NikanKhadka_2059784

/*Matrix Multiplication (15% - 100 marks)
You will create a matrix multiplication program which uses multithreading, you will be taught two
CPU multithreading concepts: POSIX threads and Open Multi-Processing (OpenMP). Matrices are
often two-dimensional arrays varying in sizes (can also be 3D), for your application, you will only
need to multiply two-dimensional ones. Your program will read in the matrix from a file (txt), store
them appropriately using dynamic memory and multiply them by splitting the tasks across “n”
threads (any number of threads via command line arguments). Each matrix will be in a separate file.
You should also use command line arguments to allow the user to enter the which matrices need to
be multiplied. The data files will be given to you however, you will need to initially identify the
dimensions of the matrix to determine whether they can be multiplied. If the matrices cannot be
multiplied, your program should notify the user. For example, if Matrix A is 3x3 and Matrix B is 2x2,
you cannot multiply them. If Matrix A is 2x3 and Matrix B is 2x2, then this can be multiplied. You will
need to research how to multiply matrices, this will also be covered in the lectures. The resulting
matrix should be outputted to a file. It is up to you which multithreading library you use (Pthreads or
OMP).*/


//compile with: gcc MatrixMultiply.c -pthread -o MatrixMultiplyExec
//run with: ./MatrixMultiplyExec Mat3.txt Mat4.txt 4
//                              file1 and file2   threads greater than 0 and less than 1000


#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>


// function declarations
int *find_number_of_rows_and_columns(const char *file_name);
void *multiply_matrices(void *args);

// limit number of threads to dimension of matrix
int max_threads_allowed;
int threadCount;

// strcuture for individual matrix elements
typedef struct
{
    double x;
} unit;


// structure to store the individual matrix rows, columns and the reference to the matrix elements
typedef struct
{
    int rows;
    int cols;
    unit *x;
} matrix;

matrix A, B, C, _C, target;
pthread_mutex_t mutex;
int thread_counter = 0;




// function to find the number of rows and columns of each matrix from the files
int *find_number_of_rows_and_columns(const char *file_name)
{
    FILE *fp = fopen(file_name, "r");
    int newRows = 1;
    int newCols = 1;
    char ch;

    static int rows_cols[10];

    while (!feof(fp))
    {
        ch = fgetc(fp);

        if (ch == '\n')
        {
            newRows++;
            // rows_cols[0] = newCols;
            newCols = 1;
        }
        else if (ch == ',')
        {
            newCols++;
        }
    }
    rows_cols[0] = newRows;
    rows_cols[1] = newCols;
    return rows_cols;
}


// function to read the matrix from the file
void display_matrix(matrix displayable_matrix)
{
    int rows = displayable_matrix.rows;
    int cols = displayable_matrix.cols;
    int i, j;
   

    for (i = 0; i < rows; i++)
    {
        printf("[  ");
        
        for (j = 0; j < cols; j++){
          printf("%lf  ", (displayable_matrix.x + i * cols + j)->x);
        }
        printf("]\n");
        
    }
    printf("\n\n");
}

// function to calculate individual matrix unit
double calculate_one_matrix_unit(int first, int second)
{
    int i;
    double result = 0.0F;
    for (i = 0; i < A.cols; i++)
    {
        result += (A.x + first * A.cols + i)->x * (B.x + i * B.cols + second)->x;
    }

    return result;
}

// function to process number of threads assigned to rows
void *multiply_matrices(void *param)
{
    while (1)
    {
        int firstNum;
        int secondNum;
        int i, j, flag = 0, close = 0;
        double res;

        pthread_mutex_lock(&mutex);
        for (i = 0; i < _C.rows; i++)
        {
            for (j = 0; j < _C.cols; j++)
            {
                if ((_C.x + i * _C.cols + j)->x == 0.0F)
                {
                    firstNum = i;
                    secondNum = j;
                    (_C.x + i * _C.cols + j)->x = 1.0F;
                    close = 1;
                    break;
                }
            }
            if (close == 1)
                break;
            else if (i == _C.rows - 1)
                flag = 1;
        }
        pthread_mutex_unlock(&mutex);

        if (flag == 1)
            pthread_exit(NULL);
        res = calculate_one_matrix_unit(firstNum, secondNum);
        (C.x + firstNum * C.cols + secondNum)->x = res;
    }
    pthread_exit(NULL);
}


//function to creare matrix
matrix create_matrix(int rows, int cols)
{
    // matrix target;
    int i, j;
    double temp_data;

    target.rows = rows;
    target.cols = cols;
    target.x = (unit *)malloc(rows * cols * sizeof(unit));
    for (i = 0; i < rows; i++)
        for (j = 0; j < cols; j++)
        {
            temp_data = 0.0F;
            (target.x + i * target.cols + j)->x = temp_data;
        }
    return target;
}






//function to write in multiplcation result in file
void writeinFile(matrix write_Matrix){
     int rows = write_Matrix.rows;
    int cols = write_Matrix.cols;
     FILE *fptr;
     fptr=fopen("2059784_MatrixOutput.txt","w");
    int i, j;
     for (i = 0; i < rows; i++)
    {
        fprintf(fptr,"[  ");
        
        for (j = 0; j < cols; j++){
          fprintf(fptr,"%lf  ", (write_Matrix.x + i * cols + j)->x);
        }

        
        fprintf(fptr,"]\n");
        
    }
    fprintf(fptr,"\n\n");
}

// function in invoked in run time
void main(int argc, char *argv[])
{
     threadCount = strtol(argv[3], NULL, 10);

    if (threadCount <= 0)
    {
        printf("Enter Number of Threads After filename1.txt and filename2.txt");
       exit(0);
    }

    FILE *fp1, *fp2 = NULL;
    int row, col;
    double matval = 0.0;
    int c;

    int MatrixA_Row, MatrixA_Col, MatrixB_Row, MatrixB_Col, MatrixC_Row, MatrixC_Col;

    char *File1 = argv[1];
    char *File2 = argv[2];

    fp1 = fopen(File1, "r");
    fp2 = fopen(File2, "r");

    if (fp1 != NULL && fp2 != NULL)
    {
        int *p;
        int *q;

        p = find_number_of_rows_and_columns(File1);

        MatrixA_Row = *(p + 0);
        MatrixA_Col = *(p + 1);

    

        q = find_number_of_rows_and_columns(File2);

        MatrixB_Row = *(q + 0);
        MatrixB_Col = *(q + 1);

        // output matrix C is the combination of rows from matrix A and columns from matrix B
        MatrixC_Row = MatrixA_Row;
        MatrixC_Col = MatrixB_Col;

    

        printf("\nMatrix on A: \tNumber of Rows: %d, Number of Columns: %d\n", MatrixA_Row, MatrixA_Col);
        printf("Matrix on B: \t Number of Rows: %d, Number of Columns: %d\n", MatrixB_Row, MatrixB_Col);
        printf("Output Matrix\t Number of Rows: %d, Number of Columns: %d\n\n", MatrixA_Row, MatrixB_Col);
        // checking matrix for multiplying
        if (MatrixA_Col == MatrixB_Row)
        {
            // elements in each matrix both row and columns
            int matA_elements = MatrixA_Row * MatrixA_Col;
            int matB_elements = MatrixB_Row * MatrixB_Col;
            int matC_elements = MatrixC_Row * MatrixC_Col;

            // dynamically allocating memory for matrix A and B
            double *Matrix_A = (double *)malloc(matA_elements * sizeof(double));
            double *Matrix_B = (double *)malloc(matB_elements * sizeof(double));

            matrix target_matA;
            target_matA.rows = MatrixA_Row;
            target_matA.cols = MatrixA_Col;
            target_matA.x = (unit *)malloc(MatrixA_Row * MatrixA_Col * sizeof(unit));

            if (Matrix_A == NULL || Matrix_B == NULL)
            {
                printf("\nError! memory not allocated.\n");
                exit(0);
            }

            // Scanning the file and storing the matrix A data in allocated memory
            int counter = 0;
            for (row = 0; row < MatrixA_Row; row++)
            {
                for (col = 0; col < MatrixA_Col; col++)
                {
                    fscanf(fp1, "%lf,", Matrix_A + counter);
                    (target_matA.x + row * target_matA.cols + col)->x = *(Matrix_A + counter);
                    counter++;
                }
            }

            printf("\n Elements of Matrix A..... \n");
            A = target_matA;
            display_matrix(A);

            matrix target_matB;
            target_matB.rows = MatrixB_Row;
            target_matB.cols = MatrixB_Col;
            target_matB.x = (unit *)malloc(MatrixB_Row * MatrixB_Col * sizeof(unit));

            // Scanning the file and storing the matrix B data in allocated memory
             counter = 0;
            for (row = 0; row < MatrixB_Row; row++)
            {
                for (col = 0; col < MatrixB_Col; col++)
                {
                    fscanf(fp2, "%lf,", Matrix_B + counter);
                    (target_matB.x + row * target_matB.cols + col)->x = *(Matrix_B + counter);
                    counter;
                }
            }

            printf("\n Elements of Matrix B..... \n");
            B = target_matB;
            display_matrix(B);

            int i;
            C = create_matrix(A.rows, B.cols);
            for (i = 0; i < C.cols * C.rows; i++)
            {
                (C.x + i)->x = 0.0F;
            }

            _C = create_matrix(A.rows, B.cols);
            for (i = 0; i < _C.cols * _C.rows; i++)
            {
                (_C.x + i)->x = 0.0F;
            }

            pthread_t thread_id[threadCount];

            printf("Creating Threads from input and Calculating the Matrix Multiplication.......\n\n");

            pthread_mutex_init(&mutex, NULL);

            for (int m = 0; m < threadCount; m++)
            {
                pthread_create(&thread_id[m], NULL, multiply_matrices, NULL);
            }

            for (int n = 0; n < threadCount; n++)
            {
                pthread_join(thread_id[n], NULL);
            }

            printf("\n\nOutput of Matrix multiplication matrix C is printed on 2059784_MatrixOutput.txt file \n");
            writeinFile(C);

            // deallocating the memory
            free(Matrix_A);
            free(Matrix_B);
            free(target_matA.x);
            free(target_matB.x);
            free(target.x);
        }
        else
        {
            printf("\nOops! Number of Columns in Matrix A is not Equal to the Number rows of Matrix B so they cant be multiplied.....\n");
        }

        fclose(fp1);
        fclose(fp2);
    }
    else
    {
        printf("\nNo such file found! Please provide the correct file name with format\n");
    }
}