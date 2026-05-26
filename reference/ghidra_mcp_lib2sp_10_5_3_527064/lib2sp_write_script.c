
void lib2sp_write_script(undefined4 param_1,int *param_2)

{
  undefined *puVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_00000014;
  int in_stack_00000018;
  
  iVar3 = param_2[1];
  iVar2 = (*(code *)PTR_realloc_00034604)(*param_2,in_stack_00000018 + iVar3);
  puVar1 = PTR_memcpy_00034610;
  if (iVar2 == 0) {
    (*(code *)PTR_lib2sp_set_error_000344f4)(param_1,7,PTR_LAB_00034444 + 0x1468);
    puVar1 = PTR_free_00034488;
    param_2[1] = 0;
    (*(code *)puVar1)(*param_2);
    *param_2 = 0;
  }
  else {
    *param_2 = iVar2;
    (*(code *)puVar1)(iVar2 + param_2[1],in_stack_00000014,in_stack_00000018);
    param_2[1] = in_stack_00000018 + iVar3;
  }
  return;
}


