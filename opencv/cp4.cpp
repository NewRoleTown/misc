#include <opencv/cv.h>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/core/core.hpp>
#include <assert.h>
#include <iostream>
#include <opencv2/imgproc.hpp>

using namespace cv;
using namespace std;


#if 0
��������ݸ�����clone��copyTo

8               U           C           3
ÿͨ��bit��     ���޷���    ����        ͨ����

3����ת������RBG2BGR,RBG2GRAY�ȵ�
    4����dstͨ������0���ʾͬsrc
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
    //ͼ�����ĵ㣬��С��˳ʱ����ת�Ƕȣ�������ʼ�����Ƚ�������ɫ���߿�����
    ellipse( img1,Point(img1.cols/2,img1.rows/2),Size(img1.cols/4,img1.rows/8),0,0,360,Scalar(0,0,0xff),2,8 );
    
    //circle
    //�ߴ�-1��ʾʵ��
    circle( img1,Point(img1.cols/2,img1.rows/2),img1.rows/4,Scalar(0xff,0,0),-1,8);
    //fillPoly,ͼ����������飬ÿ������εĵ������������
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
