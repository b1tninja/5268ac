
void lib2sp_open_file(int param_1,int *param_2,int param_3,int param_4,undefined4 param_5)

{
  undefined *puVar1;
  int iVar2;
  int *piVar3;
  undefined4 uVar4;
  int iVar5;
  undefined1 *puVar6;
  undefined *puVar7;
  undefined4 local_1110;
  undefined4 local_110c;
  undefined4 local_1108;
  undefined4 local_1100;
  undefined4 local_10fc;
  undefined4 local_10f8;
  undefined4 local_10f0;
  undefined4 local_10ec;
  undefined4 local_10e8;
  undefined4 local_10e4;
  undefined4 local_10e0;
  undefined4 local_10dc;
  undefined1 auStack_10d8 [24];
  uint local_10c0;
  undefined1 auStack_1038 [4104];
  undefined1 *local_30;
  
  puVar6 = auStack_1038;
  (*(code *)PTR_snprintf_0003690c)
            (puVar6,0x1002,PTR_LAB_00036774 + 0x331c,*(undefined4 *)(param_4 + 8),param_5);
  puVar1 = PTR_lib2sp_log_00036798;
  puVar7 = PTR_LAB_00036774;
  if ((-1 < *param_2) || (*(char *)(param_2 + 4) != '\0')) {
    (*(code *)PTR_lib2sp_set_error_0003683c)(param_1,0xb,PTR_LAB_00036774 + 0x3de0,puVar6);
    return;
  }
  param_2[5] = param_3;
  (*(code *)puVar1)(param_1,6,puVar7 + 0x3e10,puVar6);
  if (param_3 == 3) {
    do {
      local_30 = puVar6;
      iVar2 = (*(code *)PTR_stat64_000368d8)(puVar6,auStack_10d8);
      if (iVar2 == 0) {
        (*(code *)PTR_lib2sp_log_00036798)(param_1,6,PTR_LAB_00036774 + 0x3704,local_30);
        *param_2 = -1;
        *(undefined1 *)(param_2 + 4) = 1;
        return;
      }
      piVar3 = (int *)(*(code *)PTR___errno_location_00036990)();
      puVar6 = local_30;
    } while (*piVar3 == 4);
    if (*piVar3 != 2) {
      uVar4 = (*(code *)PTR_strerror_000367a8)();
      puVar7 = PTR_LAB_00036774 + 0x36e8;
      puVar6 = local_30;
      goto LAB_000190b4;
    }
    (*(code *)PTR_lib2sp_log_00036798)(param_1,6,PTR_LAB_00036774 + 0x36bc);
  }
  init_node_stats(&local_1110);
  local_10e0 = *(undefined4 *)(param_4 + 0x3c);
  local_110c = *(undefined4 *)(param_4 + 0x4c);
  local_10dc = *(undefined4 *)(param_4 + 0x40);
  local_10e4 = *(undefined4 *)(param_4 + 0x38);
  local_1110 = *(undefined4 *)(param_4 + 0x48);
  local_10fc = *(undefined4 *)(param_4 + 0x5c);
  local_1108 = *(undefined4 *)(param_4 + 0x50);
  local_1100 = *(undefined4 *)(param_4 + 0x58);
  local_10f8 = *(undefined4 *)(param_4 + 0x60);
  local_10ec = *(undefined4 *)(param_4 + 0x6c);
  local_10f0 = *(undefined4 *)(param_4 + 0x68);
  local_10e8 = *(undefined4 *)(param_4 + 0x70);
  puVar6 = auStack_1038;
  verify_path(param_1,puVar6,&local_1110);
  if (*(int *)(param_1 + 8) != 0) {
    return;
  }
  if (*(int *)(param_1 + 0x608) != 0) {
    return;
  }
  puVar7 = PTR_LAB_00036774 + 0x3730;
  do {
    while( true ) {
      iVar2 = (*(code *)PTR_open64_000367d8)(puVar6,0x301,0x1b6);
      if (-1 < iVar2) {
        iVar5 = (*(code *)PTR_stat64_000368d8)(puVar6,auStack_10d8);
        if (iVar5 == 0) {
          if ((local_10c0 & 0xf000) == 0x8000) {
            if (param_3 == 0x2f) {
              param_2[6] = 0x8000;
            }
          }
          else {
            (*(code *)PTR_lib2sp_log_00036798)
                      (param_1,6,PTR_LAB_00036774 + 0x3eb4,puVar6,local_10c0);
          }
          (*(code *)PTR_lib2sp_log_00036798)(param_1,6,PTR_LAB_00036774 + 0x3ee4,auStack_1038);
          param_2[1] = local_10c0;
          param_2[2] = 0;
          *param_2 = iVar2;
          *(undefined1 *)(param_2 + 4) = 0;
          param_2[3] = 0;
          param_2[7] = -1;
          return;
        }
        uVar4 = (*(code *)PTR_strerror_000367a8)(iVar5);
        puVar7 = PTR_LAB_00036774 + 0x3e98;
        goto LAB_000190b4;
      }
      piVar3 = (int *)(*(code *)PTR___errno_location_00036990)();
      if (*piVar3 != 0x1c) break;
      (*(code *)PTR_lib2sp_log_00036798)(param_1,4,puVar7,puVar6);
      (*(code *)PTR_lib2sp_handle_no_space_00036858)(param_1,puVar6);
      if (*(int *)(param_1 + 8) != 0) {
        return;
      }
      if (*(int *)(param_1 + 0x608) != 0) {
        return;
      }
    }
  } while (*piVar3 == 4);
  uVar4 = (*(code *)PTR_strerror_000367a8)();
  puVar7 = PTR_LAB_00036774 + 0x3e7c;
LAB_000190b4:
  (*(code *)PTR_lib2sp_set_error_0003683c)(param_1,8,puVar7,puVar6,uVar4);
  return;
}


