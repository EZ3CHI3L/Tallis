#ifndef ERROR_H
#define ERROR_H
#define DIE(format, ...) die("\n%s:%d in %s\n" format, __FILE__, __LINE__, __func__, __VA_ARGS__)
void die(const char*, ...);
#endif /* ERROR_H */
