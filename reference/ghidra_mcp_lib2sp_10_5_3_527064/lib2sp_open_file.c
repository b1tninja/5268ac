
void lib2sp_open_file(int param_1,int *param_2,int param_3,int param_4,undefined4 param_5)

{
  undefined *puVar1;
  int iVar2;
  int *piVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 *puVar6;
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
  undefined4 auStack_1038 [1026];
  undefined4 *local_30;
  
  (*(code *)PTR_snprintf_000345ac)
            (auStack_1038,0x1002,PTR_LAB_00034444 + 0x1460,*(undefined4 *)(param_4 + 8),param_5);
  puVar1 = PTR_lib2sp_log_00034464;
  puVar7 = PTR_LAB_00034444;
  if ((-1 < *param_2) || (*(char *)(param_2 + 4) != '\0')) {
    (*(code *)PTR_lib2sp_set_error_000344f4)(param_1,0xb,PTR_LAB_00034444 + 0x1f1c,auStack_1038);
    return;
  }
  param_2[5] = param_3;
  (*(code *)puVar1)(param_1,6,puVar7 + 0x1f48,auStack_1038);
  if (param_3 == 3) {
    local_30 = auStack_1038;
    do {
      iVar2 = (*(code *)PTR_stat64_00034580)(local_30,auStack_10d8);
      if (iVar2 == 0) {
        (*(code *)PTR_lib2sp_log_00034464)(param_1,6,PTR_LAB_00034444 + 0x1fa4,local_30);
        *(undefined1 *)(param_2 + 4) = 1;
        *param_2 = -1;
        return;
      }
      piVar3 = (int *)(*(code *)PTR___errno_location_00034624)();
    } while (*piVar3 == 4);
    if (*piVar3 != 2) {
      uVar4 = (*(code *)PTR_strerror_00034474)();
      puVar7 = PTR_LAB_00034444 + 0x1f88;
      puVar6 = local_30;
      goto LAB_000181e8;
    }
    (*(code *)PTR_lib2sp_log_00034464)(param_1,6,PTR_LAB_00034444 + 0x1f5c);
  }
  local_30 = &local_1110;
  (*(code *)(PTR_00034448 + 0x4bc4))(local_30);
  local_10e8 = *(undefined4 *)(param_4 + 0x70);
  local_10e0 = *(undefined4 *)(param_4 + 0x3c);
  local_10dc = *(undefined4 *)(param_4 + 0x40);
  local_10e4 = *(undefined4 *)(param_4 + 0x38);
  local_110c = *(undefined4 *)(param_4 + 0x4c);
  local_1110 = *(undefined4 *)(param_4 + 0x48);
  local_1108 = *(undefined4 *)(param_4 + 0x50);
  local_10fc = *(undefined4 *)(param_4 + 0x5c);
  local_1100 = *(undefined4 *)(param_4 + 0x58);
  local_10f8 = *(undefined4 *)(param_4 + 0x60);
  local_10ec = *(undefined4 *)(param_4 + 0x6c);
  local_10f0 = *(undefined4 *)(param_4 + 0x68);
  puVar6 = auStack_1038;
  (*(code *)(PTR_00034448 + 0x77d8))(param_1,puVar6,local_30);
  if (*(int *)(param_1 + 8) != 0) {
    return;
  }
  if (*(int *)(param_1 + 0x5c8) != 0) {
    return;
  }
  puVar7 = PTR_LAB_00034444 + 0x1fd0;
  do {
    while( true ) {
      iVar2 = (*(code *)PTR_open64_000344a4)(puVar6,0x301,0x1b6);
      if (-1 < iVar2) {
        iVar5 = (*(code *)PTR_stat64_00034580)(puVar6,auStack_10d8);
        if (iVar5 == 0) {
          if ((local_10c0 & 0xf000) == 0x8000) {
            if (param_3 == 0x2f) {
              param_2[6] = 0x8000;
            }
          }
          else {
            (*(code *)PTR_lib2sp_log_00034464)
                      (param_1,6,PTR_LAB_00034444 + 0x2028,puVar6,local_10c0);
          }
          (*(code *)PTR_lib2sp_log_00034464)(param_1,6,PTR_LAB_00034444 + 0x2054,auStack_1038);
          param_2[7] = -1;
          param_2[1] = local_10c0;
          *param_2 = iVar2;
          *(undefined1 *)(param_2 + 4) = 0;
          param_2[3] = 0;
          param_2[2] = 0;
          return;
        }
        uVar4 = (*(code *)PTR_strerror_00034474)(iVar5);
        puVar7 = PTR_LAB_00034444 + 0x2010;
        goto LAB_000181e8;
      }
      piVar3 = (int *)(*(code *)PTR___errno_location_00034624)();
      if (*piVar3 != 0x1c) break;
      (*(code *)PTR_lib2sp_log_00034464)(param_1,4,puVar7,puVar6);
      (*(code *)PTR_lib2sp_handle_no_space_00034508)(param_1,puVar6);
      if (*(int *)(param_1 + 8) != 0) {
        return;
      }
      if (*(int *)(param_1 + 0x5c8) != 0) {
        return;
      }
    }
  } while (*piVar3 == 4);
  uVar4 = (*(code *)PTR_strerror_00034474)();
  puVar7 = PTR_LAB_00034444 + 0x1ff8;
LAB_000181e8:
  (*(code *)PTR_lib2sp_set_error_000344f4)(param_1,8,puVar7,puVar6,uVar4);
  return;
}


