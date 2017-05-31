lib += aes_ctr_edit.o

INPUT25 := set4/input25.gen.txt
set4/ch25.o: $(INPUT25)
$(INPUT25): set1/ch7.out
	LD_LIBRARY_PATH=. $< > $@
