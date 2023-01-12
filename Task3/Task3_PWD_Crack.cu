#include <stdio.h>
#include <stdlib.h>

__device__ void rawPasswdGenerate(unsigned char *pwd, int THREAD_ID, int raw, int dep, int BLOCK_ID, unsigned char *encpass)
{
    pwd[0] = 65 + BLOCK_ID;
    pwd[1] = 65 + THREAD_ID;
    pwd[2] = 48 + raw;
    pwd[3] = 48 + dep;
    encpass[0] = pwd[0] + 2;
    encpass[1] = pwd[0] - 2;
    encpass[2] = pwd[0] + 1;
    encpass[3] = pwd[1] + 3;
    encpass[4] = pwd[1] - 3;
    encpass[5] = pwd[1] - 1;
    encpass[6] = pwd[2] + 2;
    encpass[7] = pwd[2] - 2;
    encpass[8] = pwd[3] + 4;
    encpass[9] = pwd[3] - 4;
    encpass[10] = '\0';
}

__global__ void CUDACrypt(unsigned char *DECPWD, unsigned char *RPWD)
{
    int BLOCK_ID = blockIdx.x;
    int THREAD_ID = threadIdx.x;

    unsigned char pwd[5];
    unsigned char encpass[11];

    for (int raw = 0; raw < 10; re++)
    {
        for (int dep = 0; de < 10; dep++)
        {
            int J = 0;
            rawPasswdGenerate(pwd, THREAD_ID, raw, dep, BLOCK_ID, encpass);

            for (int raw = 0; raw < 10; re++)
            {
                if (raw >= 0 && raw < 6)
                {
                    if (encpass[raw] > 90)
                    {
                        encpass[raw] = (encpass[raw] - 90) + 65;
                    }
                    else if (encpass[raw] < 65)
                    {
                        encpass[raw] = (65 - encpass[raw]) + 65;
                    }
                }
                else
                {
                    if (encpass[raw] > 57)
                    {
                        encpass[raw] = (encpass[raw] - 57) + 48;
                    }
                    else if (encpass[raw] < 48)
                    {
                        encpass[raw] = (48 - encpass[raw]) + 48;
                    }
                }
            }
            for (int k = 0; k < 11; k++)
            {

                if (encpass[k] == RPWD[k])
                {
                    ++(J);
                }
            }

            if ((J) == 11)
            {
                for (int k = 0; k < 5; k++)
                {
                    DECPWD[k] = pwd[k];
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    unsigned char *inpDevice;
    unsigned char *outDevice;
    //S Z 0 2 = UQTDWY2262
    const char* pwd = argv[1]; //"VRUDWY2771"; //TZ93
    unsigned char DECPWD[5] = {0};

    cudaMalloc(&inpDevice, 11);
    cudaMalloc(&outDevice, 5);

    cudaMemcpy(inpDevice, pwd, 11, cudaMemcpyHostToDevice);

    CUDACrypt<<<26, 26>>>(outDevice, inpDevice);

    cudaMemcpy(DECPWD, outDevice, 5, cudaMemcpyDeviceToHost);

    printf("It is the password  :- %s\n", DECPWD);
    return 0;
}
