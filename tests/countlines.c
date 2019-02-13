//functions to make the compiler generate fancy instructions
int countlines(char *src, long len) {
    int lines = 0;
    for (int i=0; i<len; i++) {
        if (src[i] == '\n')
            lines++;
    }
    return lines;
}
int countchars(char *src, long len, unsigned char c) {
    int occ = 0;
    for (int i=0; i<len; i++) {
        if (src[i] == c)
            occ++;
    }
    return occ;
}
