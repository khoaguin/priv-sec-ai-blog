#pragma once

#include <iostream>
#include <iomanip>

namespace utils
{
    /*
    Helper function: Print line number.
    */
    inline void print_line(int line_number)
    {
        std::cout << "Line " << std::setw(3) << line_number << " --> ";
    }
}
