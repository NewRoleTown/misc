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
    //�˴�С��ê���λ�ã�Ĭ��-1,-1��ʾ���ģ����Ƿ�Ϊ��һ��,Ĭ�Ϲ�һ������ͬ�ھ�ֵ�˲�
    //boxFilter( img1,img2,-1,Size(3,3),Point(-1,-1),1 );
    //GaussianBlur( img1,img2,Size(5,5),500,500 );
    //medianBlur( img1,img2,7);
    dilate( img1,img2,getStructuringElement(MORPH_RECT,Size(5,5),Point(2,2)) ); 
    erode( img1,img2,getStructuringElement(MORPH_RECT,Size(5,5),Point(2,2)) ); 
    morphologyEx( img1,img2,MORPH_GRADIENT,getStructuringElement(MORPH_RECT,Size(5,5),Point(2,2)) ); 
    morphologyEx( img1,img2,MORPH_ERODE,getStructuringElement(MORPH_RECT,Size(5,5),Point(2,2)) ); 

    morphologyEx( img1,img2,MORPH_GRADIENT,getStructuringElement(MORPH_RECT,Size(5,5),Point(2,2)) ); 

#endif
    //���ʹ�����룬�������Size��(width+2,height+2)
    //4�η������ľ��δ�С
    //5��Ϊ���Խ��ܵĸ���ɫ����
    //6����ƫ��
    //7������ʮ����ͨ����������ͨ
    //Rect rect;
    //int ret = floodFill( img1,Point(0,0),Scalar(0xff,0,0),&rect,Scalar(0xff,0xff,0xff),Scalar(0xff,0xff,0xff));
    //cout<<rect<<endl;
   

    //���ָ����size��fx��fy��û����
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
    //����Ϊ��ֵ��4���Ǹ�5���õģ�5�ξ�����������CV_THRESH_BINARY��ʾ�����ֵС����ֵ����4�δ��棬����Ϊ0
    threshold( img1,img2,128,255,CV_THRESH_BINARY );


    imshow( "example2",img2 );
    imshow( "example1",img1 );
    waitKey();
}

int main(){

    sblur();

    return 0;
}
