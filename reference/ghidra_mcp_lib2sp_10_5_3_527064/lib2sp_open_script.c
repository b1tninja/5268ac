
void lib2sp_open_script(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4)

{
  undefined4 uStack00000010;
  
  uStack00000010 = param_4;
                    /* WARNING: Could not recover jumptable at 0x00014bbc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*(code *)PTR_lib2sp_log_00034464)
            (param_1,6,PTR_LAB_00034444 + 0x1450,*(undefined4 *)(param_3 + 0xc));
  return;
}


