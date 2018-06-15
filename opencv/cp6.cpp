#include <opencv/cv.h>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/core/core.hpp>
#include <assert.h>
#include <iostream>
#include <opencv2/imgproc.hpp>

using namespace cv;
using namespace std;


void sblur(){
    Mat img1 = imread( "./1" );
    Mat img2;

#if 0
    //核大小，锚点的位置，默认-1,-1表示中心，核是否为归一化,默认归一化，等同于均值滤波
    //boxFilter( img1,img2,-1,Size(3,3),Point(-1,-1),1 );
    //GaussianBlur( img1,img2,Size(5,5),500,500 );
    //medianBlur( img1,img2,7);
    dilate( img1,img2,getStructuringElement(MORPH_RECT,Size(5,5),Point(2,2)) ); 
    erode( img1,img2,getStructuringElement(MORPH_RECT,Size(5,5),Point(2,2)) ); 
    morphologyEx( img1,img2,MORPH_GRADIENT,getStructuringElement(MORPH_RECT,Size(5,5),Point(2,2)) ); 
    morphologyEx( img1,img2,MORPH_ERODE,getStructuringElement(MORPH_RECT,Size(5,5),Point(2,2)) ); 

    morphologyEx( img1,img2,MORPH_GRADIENT,getStructuringElement(MORPH_RECT,Size(5,5),Point(2,2)) ); 

#endif
    //如果使用掩码，则掩码的Size是(width+2,height+2)
    //4参返回填充的矩形大小
    //5参为可以接受的负颜色便宜
    //6参正偏移
    //7参设置十字联通还是米字联通
    //Rect rect;
    //int ret = floodFill( img1,Point(0,0),Scalar(0xff,0,0),&rect,Scalar(0xff,0xff,0xff),Scalar(0xff,0xff,0xff));
    //cout<<rect<<endl;
   

    //如果指定了size，fx和fy就没用了
#if 0 
    resize( img1,img2,Size(),0.5,0.5);
    resize( img2,img2,Size(),0.5,0.5);
    resize( img2,img2,Size(),0.5,0.5);
    resize( img2,img2,Size(),0.5,0.5);
    resize( img2,img2,Size(),2,2);
    resize( img2,img2,Size(),2,2);
    resize( img2,img2,Size(),2,2);
    resize( img2,img2,Size(),2,2);
#endif


    //pyrDown( img1,img2 );
    //pyrUp( img2,img2 );


    img1 = imread("./1",0);
    //三参为阈值，4参是给5参用的，5参决定操作，如CV_THRESH_BINARY表示，如果值小于阈值，用4参代替，否则为0
    threshold( img1,img2,128,255,CV_THRESH_BINARY );


    imshow( "example2",img2 );
    imshow( "example1",img1 );
    waitKey();
}

int main(){

    sblur();

    return 0;
}
