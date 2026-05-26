
void lib2sp_mkpath(int param_1,undefined4 param_2,undefined4 param_3,char *param_4,char *param_5)

{
  int iVar1;
  undefined *puVar2;
  char *pcVar3;
  
  pcVar3 = *(char **)(param_1 + 0x668);
  if (((pcVar3 == (char *)0x0) || (*pcVar3 == '\0')) ||
     ((iVar1 = (*(code *)PTR_strlen_000345b8)(pcVar3), iVar1 == 1 &&
      (iVar1 = (*(code *)PTR_strcmp_000344a0)(pcVar3,PTR_LAB_00034444 + 0x178c), iVar1 != 0)))) {
    puVar2 = PTR_LAB_00034444 + 0x1460;
    pcVar3 = param_4;
  }
  else {
    puVar2 = PTR_LAB_00034444 + 0x1790;
    param_5 = param_4;
  }
  (*(code *)PTR_snprintf_000345ac)(param_2,param_3,puVar2,pcVar3,param_5);
                    /* WARNING: Could not recover jumptable at 0x00016064. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*(code *)PTR_strlen_000345b8)(param_2);
  return;
}


