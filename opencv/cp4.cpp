#include <opencv/cv.h>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/core/core.hpp>
#include <assert.h>
#include <iostream>
#include <opencv2/imgproc.hpp>

using namespace cv;
using namespace std;


#if 0
矩阵的数据复制用clone或copyTo

8               U           C           3
每通道bit数     有无符号    类型        通道数

3参是转换规则RBG2BGR,RBG2GRAY等等
    4参是dst通道数，0则表示同src
cvtColor( InputArray src,OutputArray dst,int code,int dstCn )
#endif

    void Transform(){
        Mat img1 = imread("./1");
        Mat dst;
        cvtColor( img1,dst,COLOR_RGB2GRAY);
        imshow("example",dst );

        waitKey(0);
        return;
    }

void sMat(){
    Mat M(3,2,CV_8UC3,Scalar(0,0,255));
    cout<<M<<endl;

    Mat img1 = imread("./1",0);
    Mat mtx(img1);
    cout<<endl<<mtx<<endl;

    mtx.create(3,3,CV_8UC3);
    cout<<endl<<mtx<<endl;

    return;
}


void Shape(){
    Mat img1 = imread("./1");


    //line
    line(img1,Point(0,0),Point(img1.cols,img1.rows),Scalar(0,0xff,0),1,8 );
    
    //ellipse
    //图，中心点，大小，顺时针旋转角度，弧度起始，弧度结束，颜色，线宽，线型
    ellipse( img1,Point(img1.cols/2,img1.rows/2),Size(img1.cols/4,img1.rows/8),0,0,360,Scalar(0,0,0xff),2,8 );
    
    //circle
    //线粗-1表示实心
    circle( img1,Point(img1.cols/2,img1.rows/2),img1.rows/4,Scalar(0xff,0,0),-1,8);
    //fillPoly,图，多边形数组，每个多边形的点数，多边形数
    Point points[1][4];
    points[0][0] = Point( 20,20 );
    points[0][1] = Point( 80,20 );
    points[0][2] = Point( 80,80 );
    //points[0][3] = Point( 20,80 );

    const Point *ppt[] = {points[0]};
    int npt[] = {3};
    fillPoly( img1,ppt,npt,1,Scalar(0,0xff,0),8 );


    imshow("example",img1 );
    waitKey(0);
    return;
}

int main(){
    //sMat();
    //Transform();
    Shape();
    return 0;
}
