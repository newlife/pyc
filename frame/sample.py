import sys

def simple_add(a,b):
    print("function")
    print(sys._getframe())
    print(sys._getframe().f_back)
    return a+b

if __name__ == '__main__':
    print("main")
    print(sys._getframe())
    print(sys._getframe().f_back)
    r = simple_add(1,2)
