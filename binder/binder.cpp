#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/complex.h>

#include "../src/troy_cuda.cuh"
#include <iostream>

namespace py = pybind11;

using namespace troyn;

class Smoke {
public:
    int t;
    Smoke(int i) {t=i;}
    Smoke() {t=19991111;}
    void print() {std::cout << "Hello I am Smoking ... " << t << std::endl;}
};

PYBIND11_MODULE(pytroy, m) {
    
    py::class_<Smoke>(m, "Smoke")
        .def(py::init<>())
        .def(py::init<int>())
        .def("hello", &Smoke::print);
    
    py::class_<Plaintext>(m, "Plaintext")
		.def("parms_id", py::overload_cast<>(&Plaintext::parmsID, py::const_), py::return_value_policy::reference);

}