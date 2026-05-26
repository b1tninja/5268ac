
void lib2sp_close_file(int param_1,int *param_2,uint *param_3,undefined4 param_4)

{
  undefined *puVar1;
  undefined *puVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  uint local_1068;
  uint local_1064;
  uint local_1060;
  uint local_1058;
  uint local_1054;
  uint local_1050;
  uint local_1048;
  uint local_1044;
  uint local_1040;
  uint local_103c;
  uint local_1038;
  uint local_1034;
  undefined1 auStack_1030 [4104];
  uint *local_28;
  
  (*(code *)PTR_snprintf_000345ac)(auStack_1030,0x1002,PTR_LAB_00034444 + 0x1460,param_3[2],param_4)
  ;
  puVar2 = PTR_lib2sp_log_00034464;
  puVar1 = PTR_LAB_00034444;
  if (*(char *)(param_2 + 4) == '\0') {
    iVar7 = *param_2;
    if (iVar7 < 0) {
      if (*(int *)(param_1 + 8) == 0) {
        (*(code *)PTR_lib2sp_log_00034464)(param_1,4,PTR_LAB_00034444 + 0x1718);
      }
    }
    else {
      iVar3 = (*(code *)PTR_fsync_00034478)(iVar7);
      if (iVar3 != 0) {
        puVar4 = (undefined4 *)(*(code *)PTR___errno_location_00034624)();
        uVar5 = (*(code *)PTR_strerror_00034474)(*puVar4);
        (*(code *)PTR_lib2sp_log_00034464)(param_1,4,PTR_LAB_00034444 + 0x1740,auStack_1030,uVar5);
      }
      iVar7 = (*(code *)PTR_close_00034528)(iVar7);
      if (iVar7 != 0) {
        puVar4 = (undefined4 *)(*(code *)PTR___errno_location_00034624)();
        uVar5 = (*(code *)PTR_strerror_00034474)(*puVar4);
        (*(code *)PTR_lib2sp_log_00034464)(param_1,4,PTR_LAB_00034444 + 0x175c,auStack_1030,uVar5);
      }
      local_28 = &local_1068;
      (*(code *)(PTR_00034448 + 0x4bc4))(local_28);
      local_1038 = param_3[0xf];
      local_1050 = param_3[0x18];
      local_1040 = param_3[0x1c];
      local_1034 = param_3[0x10];
      local_103c = param_3[0xe];
      local_1064 = param_3[0x13];
      local_1068 = param_3[0x12];
      local_1060 = param_3[0x14];
      local_1054 = param_3[0x17];
      local_1058 = param_3[0x16];
      local_1044 = param_3[0x1b];
      local_1048 = param_3[0x1a];
      (*(code *)(PTR_00034448 + 0x5874))(param_1,auStack_1030,local_28,1);
      if ((*param_3 & 0x10000) != 0) {
        uVar6 = param_3[2];
        *(undefined4 *)(param_1 + 0x644) = param_4;
        *(uint *)(param_1 + 0x648) = uVar6;
      }
      *param_2 = -1;
      puVar2 = PTR_lib2sp_log_00034464;
      puVar1 = PTR_LAB_00034444;
      uVar6 = param_3[2];
      param_2[3] = 0;
      param_2[2] = 0;
      *(undefined1 *)(param_2 + 4) = 0;
      (*(code *)puVar2)(param_1,6,puVar1 + 0x1778,uVar6,param_4);
    }
  }
  else {
    *param_2 = -1;
    *(undefined1 *)(param_2 + 4) = 0;
    (*(code *)puVar2)(param_1,6,puVar1 + 0x16f0,auStack_1030);
  }
  return;
}


