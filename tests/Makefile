SRC := countlines.c
PY3 := python3
.PHONY: multiobj all tests tests1 clean
all: tests
multiobj: $(SRC)
	@rm *.txt 2>/dev/null; \
	for arg in $(SRC); do \
		objname="$$(echo "$$arg" | sed 's/.c//')"; \
		avx2_obj="$$objname""_avx2.o"; \
		sse2_obj="$$objname""_sse2.o"; \
		$(CC) -c -o "$$avx2_obj" -march=skylake -mtune=skylake -O3 $$arg || exit 1; \
		$(CC) -c -o "$$sse2_obj" -march=core2 -mtune=core2 -O3 $$arg || exit 1; \
		echo "$$avx2_obj" >> avx2.txt; \
		echo "$$sse2_obj" >> sse2.txt; \
	done

tests1: multiobj
	@while read filename; do \
		$(PY3) ../main.py --summary "$$filename" | grep -qi 'avx2:' || (echo "failed to match avx2" ; exit 1;) || exit 1; \
	done < avx2.txt; 
	@while read filename; do \
		$(PY3) ../main.py --summary "$$filename" | grep -qi 'sse2:' || (echo "failed to match sse2" ; exit 1;) || exit 1; \
	done < sse2.txt; 
tests: tests1
	@echo "Tests succeded"

clean:
	rm *.txt *.o 2>/dev/null
