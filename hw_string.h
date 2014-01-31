
#ifndef __HW_HW_STRING_H__
#define __HW_HW_STRING_H__

hw_string* create_string(const char* value);
void append_string(hw_string* destination, hw_string* source);
void string_from_int(hw_string* str, int val, int base);

#endif /* __HW_HW_STRING_H__ */
