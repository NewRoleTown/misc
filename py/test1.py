import numpy as np
import h5py
import matplotlib
import matplotlib.pyplot as plt
import pylab
    
def load_dataset():
    train_dataset = h5py.File('./train_catvnoncat.h5', "r")
    train_set_x_orig = np.array(train_dataset["train_set_x"][:]) # your train set features
    train_set_y_orig = np.array(train_dataset["train_set_y"][:]) # your train set labels

    test_dataset = h5py.File('./test_catvnoncat.h5', "r")
    test_set_x_orig = np.array(test_dataset["test_set_x"][:]) # your test set features
    test_set_y_orig = np.array(test_dataset["test_set_y"][:]) # your test set labels

    classes = np.array(test_dataset["list_classes"][:]) # the list of classes
    
    train_set_y_orig = train_set_y_orig.reshape((1, train_set_y_orig.shape[0]))
    test_set_y_orig = test_set_y_orig.reshape((1, test_set_y_orig.shape[0]))
    
    return train_set_x_orig, train_set_y_orig, test_set_x_orig, test_set_y_orig, classes

def sigmoid(z):
	return 1/(1+np.exp(-z))

def init_with0(dim):
	w = np.zeros(shape = (dim,1))
	b = 0;
	return (w,b)

#X = (n,m)
#w = (n,1)
def propagate(w,b,X,Y):

	m = X.shape[1]
	#z = w.t * x + b

	A = sigmoid(np.dot(w.T,X) + b)
	cost = (-1/m) * np.sum( Y * np.log(A) + (1 - Y) * np.log(1 - A) )

	dw = (1/m) * np.dot(X,(A - Y).T)
	db = (1/m) * np.sum(A - Y)

	return dw,db,cost

train_set_x_orig, train_set_y, test_set_x_orig, test_set_y, classes = load_dataset()

m_train = train_set_y.shape[1] #训练集里图片的数量。
m_test = test_set_y.shape[1] #测试集里图片的数量。
num_px = train_set_x_orig.shape[1]#训练、测试集里面的图片的宽度和高度（均为64x64）。

train_set_x_flatten = train_set_x_orig.reshape( train_set_x_orig.shape[0],-1 ).T
test_set_x_flatten = test_set_x_orig.reshape( test_set_x_orig.shape[0],-1 ).T

train_set_x = train_set_x_flatten / 255
test_set_x = test_set_x_flatten / 255

def optimize(w , b , X , Y , num_iterations , learning_rate , print_cost = False):

	costs = []

	for i in range(num_iterations):
		dw,db,cost = propagate(w,b,X,Y)
		w = w - learning_rate * dw
		b = b - learning_rate * db
		if i % 100 == 0 :
			costs.append(cost)
	return w,b,costs

def predict(w , b , X ):
	m = X.shape[1]

	z = np.dot(w.T,X) + b
	a = sigmoid(z)



