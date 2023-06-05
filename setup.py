from distutils.core import setup
from Cython.Build import cythonize

# pip3 install Cython
# python setup.py build_ext --inplace  当前目录下加密
setup(ext_modules=cythonize(["app/encrypt.py", "app/views.py", "app/models.py"]))