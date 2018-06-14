#include <opencv/cv.h>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/core/core.hpp>
#include <assert.h>
#include <iostream>
#include <opencv2/imgproc.hpp>

using namespace cv;
using namespace std;


#if 0
二维mat中step.p[0]是行的大小
inline
uchar* Mat::ptr(int y)
{
    CV_DbgAssert( y == 0 || (data && dims >= 1 && (unsigned)y < (unsigned)size.p[0]) );
    return data + step.p[0] * y;
}
#endif

void mat_operation(){
    Mat mat = imread("./1");

    //1
    for( int i = 0; i < mat.rows; i++ ){
        uchar *data = mat.ptr(i);
        for( int j = 0; j < mat.cols * mat.channels(); j++ ){
            data[j] = 10 * (data[j]/10);
        }
    }


    //2
    Mat_<Vec3b>::iterator it = mat.begin<Vec3b>();
    Mat_<Vec3b>::iterator itend = mat.end<Vec3b>();
    while( it != itend ){
        (*it)[0]++;
        (*it)[1]++;
        (*it)[2]++;
        it++;
    }


    //3
    for( int i = 0; i < mat.rows; i++ ){
        for( int j = 0; j < mat.cols; j++ ){
            mat.at<Vec3b>(i,j)[0] += 2;
            mat.at<Vec3b>(i,j)[1] += 2;
            mat.at<Vec3b>(i,j)[2] += 2;
        }
    }


    imshow("example",mat);
    waitKey();

}

void roi(){
    Mat src = imread("./tmp.jpg");
    Mat ico = imread("./3");
    Mat roi = src(Rect(0,0,ico.cols,ico.rows));
    Mat mask = imread("./3",0);

    int x = 1;
    for( int i = 0; i < mask.rows/2; i++ ){
        uchar *data = mask.ptr(i);
        for( int j = 0; j < mask.cols * mask.channels(); j++ ){
            data[j] = 1;
        }
    }

    //mask对应位为1则copy
    ico.copyTo( roi,mask );
    imshow("example",src);
    waitKey();
}


void splitchannel(){
    Mat src = imread("./tmp.jpg");
    Mat dst;
    vector<Mat> channels;
    split( src,channels );


    //merge(channels,dst);
    imshow("example",channels[2]);
    waitKey();
}

int main(){


    mat_operation();
    //roi();
    //splitchannel();

    return 0;
}
