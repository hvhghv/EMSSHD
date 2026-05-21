$(TARGET): $(OBJ_DIR_1) $(OBJ_C_1)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_DIR_1) $(OBJ_C_1) $(LIB)
