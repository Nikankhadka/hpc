// while opening the image,Please zoom in to see the piture. same for the output image file.


#include <stdio.h>
#include <stdlib.h>
#include "lodepng.h"



__device__ unsigned int deviceWidth;

__device__ unsigned char getRed(unsigned char *image, unsigned int row, unsigned int col)
{
  unsigned int i = (row * deviceWidth * 4) + (col * 4);
  return image[i];
}

__device__ unsigned char getGreen(unsigned char *image, unsigned int row, unsigned int col)
{
  unsigned int i = (row * deviceWidth * 4) + (col * 4) + 1;
  return image[i];
}

__device__ unsigned char getBlue(unsigned char *image, unsigned int row, unsigned int col)
{
  unsigned int i = (row * deviceWidth * 4) + (col * 4) + 2;
  return image[i];
}

__device__ unsigned char getAlpha(unsigned char *image, unsigned int row, unsigned int col)
{
  unsigned int i = (row * deviceWidth * 4) + (col * 4) + 3;
  return image[i];
}

__device__ void setRed(unsigned char *image, unsigned int row, unsigned int col, unsigned char red)
{
  unsigned int i = (row * deviceWidth * 4) + (col * 4);
  image[i] = red;
}

__device__ void setGreen(unsigned char *image, unsigned int row, unsigned int col, unsigned char green)
{
  unsigned int i = (row * deviceWidth * 4) + (col * 4) + 1;
  image[i] = green;
}

__device__ void setBlue(unsigned char *image, unsigned int row, unsigned int col, unsigned char blue)
{
  unsigned int i = (row * deviceWidth * 4) + (col * 4) + 2;
  image[i] = blue;
}

__device__ void setAlpha(unsigned char *image, unsigned int row, unsigned int col, unsigned char alpha)
{
  unsigned int i = (row * deviceWidth * 4) + (col * 4) + 3;
  image[i] = alpha;
}

__global__ void changeImage(unsigned char* image, unsigned char* newImage, unsigned int *width){
  int row = blockIdx.x+1;
  int col = threadIdx.x+1;

  deviceWidth = *width;
  
  unsigned redTL, redTC, redTR;
  unsigned redL, redC, redR;
  unsigned redBL, redBC, redBR;
  unsigned newRed;

  unsigned greenTL, greenTC, greenTR;
  unsigned greenL, greenC, greenR;
  unsigned greenBL, greenBC, greenBR;
  unsigned newGreen;

  unsigned blueTL, blueTC, blueTR;
  unsigned blueL, blueC, blueR;
  unsigned blueBL, blueBC, blueBR;
  unsigned newBlue;
  
  setGreen(newImage, row, col, getGreen(image, row, col));
  setBlue(newImage, row, col, getBlue(image, row, col));
  setAlpha(newImage, row, col, 255);

  redTL = getRed(image, row - 1, col - 1);
  redTC = getRed(image, row - 1, col);
  redTR = getRed(image, row - 1, col + 1);

  redL = getRed(image, row, col - 1);
  redC = getRed(image, row, col);
  redR = getRed(image, row, col + 1);

  redBL = getRed(image, row + 1, col - 1);
  redBC = getRed(image, row + 1, col);
  redBR = getRed(image, row + 1, col + 1);

  newRed = (redTL+redTC+redTR+redL+redC+redR+redBL+redBC+redBR)/9;

  setRed(newImage, row, col, newRed);

  greenTL = getGreen(image, row - 1, col - 1);
  greenTC = getGreen(image, row - 1, col);
  greenTR = getGreen(image, row - 1, col + 1);

  greenL = getGreen(image, row, col - 1);
  greenC = getGreen(image, row, col);
  greenR = getGreen(image, row, col + 1);

  greenBL = getGreen(image, row + 1, col - 1);
  greenBC = getGreen(image, row + 1, col);
  greenBR = getGreen(image, row + 1, col + 1);

  newGreen = (greenTL+greenTC+greenTR+greenL+greenC+greenR+greenBL+greenBC+greenBR)/9;

  setGreen(newImage, row, col, newGreen);

  blueTL = getBlue(image, row - 1, col - 1);
  blueTC = getBlue(image, row - 1, col);
  blueTR = getBlue(image, row - 1, col + 1);

  blueL = getBlue(image, row, col - 1);
  blueC = getBlue(image, row, col);
  blueR = getBlue(image, row, col + 1);

  blueBL = getBlue(image, row + 1, col - 1);
  blueBC = getBlue(image, row + 1, col);
  blueBR = getBlue(image, row + 1, col + 1);

  newBlue = (blueTL+blueTC+blueTR+blueL+blueC+blueR+blueBL+blueBC+blueBR)/9;

  setBlue(newImage, row, col, newBlue);
}



int main(int argc, char **argv)
{
    unsigned char *image;
  const char *filename = argv[1];
  const char *newFileName = "output.png";
  unsigned char *newImage;
  unsigned int height = 0, width = 0;
  
  
  lodepng_decode32_file(&image, &width, &height, filename);
  newImage = (unsigned char *)malloc(height * width * 4 * sizeof(unsigned char));

  unsigned char * gpuImage;
  cudaMalloc( (void**) &gpuImage, sizeof(char) * height*width*4); 
  cudaMemcpy(gpuImage, image, sizeof(char) *  height*width*4, cudaMemcpyHostToDevice);

  unsigned char * gpuNewImage;
  cudaMalloc( (void**) &gpuNewImage, sizeof(char) * height*width*4);

  unsigned int* gpuWidth; 
  cudaMalloc( (void**) &gpuWidth, sizeof(int));
  cudaMemcpy(gpuWidth, &width, sizeof(int), cudaMemcpyHostToDevice);

  //Use the gussian blur
  changeImage<<<height-1,width-1>>>(gpuImage, gpuNewImage, gpuWidth);
  cudaDeviceSynchronize();

  cudaMemcpy(newImage, gpuNewImage, sizeof(char) * height * width * 4, cudaMemcpyDeviceToHost);

  lodepng_encode32_file(newFileName, newImage, width, height);
  return 0;
}
