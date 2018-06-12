#include <opencv/cv.h>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/core/core.hpp>
#include <assert.h>
#include <iostream>
#include <opencv2/imgproc.hpp>

using namespace cv;
using namespace std;


void createAlphaMat( Mat &mat ){

    for( int i = 0; i < mat.rows; i++ ){
        for( int j = 0; j < mat.cols; j++ ){
            //˳����b,g,r,a
            Vec4b &rgba = mat.at<Vec4b>(i,j);
            rgba[0] = 0x0;
            rgba[1] = 0x0;
            rgba[2] = 0xff;
            rgba[3] = 0x0;
        }
    }

    return;
}


void funsion(){
    Mat img1 = imread("./1");
    Mat img2 = imread("./2");
    cvNamedWindow( "example1",CV_WINDOW_AUTOSIZE );
    cvNamedWindow( "example2",CV_WINDOW_AUTOSIZE );

    
    //��ʼ��ƫ�ƣ���ƫ�ƣ����С���ݴ�С
    Mat imageRoi = img2( Rect(160,0,128,128) );
    addWeighted( imageRoi,0.1,img1,0.3,0.0,imageRoi );

    imshow("example2",img2 );
    waitKey();

    return;
}



int g_draw = 0;
Rect g_rectangle;
void DrawRectangle( Mat &img,Rect &box ){
    //hdc,���Ͻ�point�����½�point,��ɫ���ߴ֣�����
    rectangle( img,box.tl(),box.br(),Scalar(0xff,0x0,0),3,20 );
    return;
}


void MouseCallBack( int event,int x,int y,int flags,void *param ){

    if( event == EVENT_LBUTTONDOWN ){
        g_rectangle = Rect(x,y,0,0);
        g_draw = 1;
    }else if( event == EVENT_LBUTTONUP ){
        g_draw = 0;
        if( g_rectangle.width < 0 ){
            g_rectangle.x += g_rectangle.width;
            g_rectangle.width *= -1;
        }
        if( g_rectangle.height < 0 ){
            g_rectangle.y += g_rectangle.height;
            g_rectangle.height *= -1;
        }
        DrawRectangle( *(Mat *)param,g_rectangle );
    }else if( event == EVENT_MOUSEMOVE ){
        if( g_draw == 1 ){
            g_rectangle.width = x - g_rectangle.x;
            g_rectangle.height = y - g_rectangle.y;
        }
    }else{
        return;
    }
    return;
}


int main( int argc, char** argv )
{

    //�ڶ���������ʾɫ��ͨ��,Ĭ��ֵ1��ʾ3ͨ����ɫ/higui_c.h
    //0Ϊ8bit�Ҷ�ͼ
    Mat BackGround(600,800,CV_8UC3);

    //�ڶ�������Ĭ��CV_WINDOW_AUTOSIZE
    cvNamedWindow( "example",CV_WINDOW_AUTOSIZE );

    imshow("example",BackGround );

    setMouseCallback( "example",MouseCallBack,&BackGround );
    //waitKey();
    while(1){
        imshow("example",BackGround );
        if( waitKey( 10 ) == 27 )
            break;
    }

#if 0
    //�ߣ���ɫ������
    Mat pic(320,640,CV_8UC4);
    createAlphaMat( pic );

    //һ��Ҫ����׺
    //bool imwrite( const string &filenam,InputArray img,const vector<int>& params = vector<int>() );
    //�������ض���ʽ�Ĳ�������,��ѹ��һ��flag�����壬֮��ѹ��jpegΪ0-100��������pngΪ0-9ѹ������ȵ�
    //bool imwrite( const string &filenam,InputArray img,const vector<int>& params = vector<int>() );
    //ret = 1Ϊ�ɹ�
    int ret = imwrite( "tmp.jpg",pic );

#endif


    //funsion();


    return 0;
}
