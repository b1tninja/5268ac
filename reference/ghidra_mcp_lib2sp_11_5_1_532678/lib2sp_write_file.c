
void lib2sp_write_file(int param_1,int *param_2,int param_3,undefined4 param_4,int param_5,
                      int param_6)

{
  undefined *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  int *piVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  longlong lVar11;
  undefined1 auStack_1044 [4];
  int local_1040;
  undefined1 auStack_103c [4100];
  int local_38;
  int local_34;
  uint local_30;
  int local_2c;
  
  if (*(char *)(param_2 + 4) != '\0') {
    return;
  }
  iVar9 = *param_2;
  if (iVar9 < 0) {
    (*(code *)PTR_lib2sp_set_error_0003683c)(param_1,0xb,PTR_LAB_00036774 + 0x3a8c);
    return;
  }
  (*(code *)PTR_snprintf_0003690c)
            (auStack_103c,0x1002,PTR_LAB_00036774 + 0x331c,*(undefined4 *)(param_3 + 8),param_4);
  (*(code *)PTR_lib2sp_check_space_0003699c)(param_1,auStack_103c,&local_1040);
  if (*(int *)(param_1 + 8) != 0) {
    return;
  }
  if (*(int *)(param_1 + 0x608) != 0) {
    return;
  }
  lVar11 = (*(code *)PTR_lseek64_000368f4)(iVar9);
  if (lVar11 == *(longlong *)(param_2 + 2)) {
    local_38 = param_2[7];
  }
  else if ((param_2[1] & 0xf000U) == 0x8000) {
    (*(code *)PTR_printf_000367a4)
              (PTR_LAB_00036774 + 0x3aa4,0x8000,(int)((ulonglong)lVar11 >> 0x20),(int)lVar11,
               param_2[2],param_2[3]);
    (*(code *)PTR_lib2sp_log_00036798)(param_1,4,PTR_LAB_00036774 + 0x3abc);
    local_38 = param_2[7];
  }
  else {
    local_38 = param_2[7];
  }
  local_34 = param_2[8];
  (*(code *)PTR_memcpy_00036978)(auStack_1044,param_2 + 9,4);
  iVar10 = 0;
LAB_0001a750:
  do {
    if (param_6 <= iVar10) {
      return;
    }
    uVar8 = param_6 - iVar10;
    if (((param_2[1] & 0xf000U) == 0x8000) && (param_2[5] == 0x2f)) {
      uVar2 = param_2[7];
      if ((int)uVar2 < 0) {
        local_30 = 4 - param_2[8];
        if ((int)uVar8 <= (int)local_30) {
          local_30 = uVar8;
        }
        (*(code *)PTR_memcpy_00036978)((int)param_2 + param_2[8] + 0x24,param_5 + iVar10,local_30);
        iVar3 = param_2[8];
        iVar10 = iVar10 + local_30;
        param_2[8] = local_30 + iVar3;
        if (3 < local_30 + iVar3) {
          uVar8 = param_2[9];
          if ((uint)param_2[6] < uVar8) {
            local_30 = uVar8;
            (*(code *)PTR_printf_000367a4)(PTR_LAB_00036774 + 0x3ae0,uVar8);
            (*(code *)PTR_lib2sp_set_error_0003683c)
                      (param_1,8,PTR_LAB_00036774 + 0x3af4,*(undefined4 *)(param_3 + 8),param_4,
                       local_30,param_2[6]);
            goto LAB_0001a768;
          }
          param_2[7] = uVar8;
        }
        goto LAB_0001a750;
      }
      if ((int)uVar2 < (int)uVar8) {
        uVar8 = uVar2;
      }
    }
    if ((uint)(local_1040 - iVar10) < uVar8) {
      uVar8 = local_1040 - iVar10;
    }
    if ((int)uVar8 < 1) {
      (*(code *)PTR_lib2sp_check_space_0003699c)(param_1,auStack_103c,&local_1040);
      if (*(int *)(param_1 + 8) != 0) {
LAB_0001a768:
        iVar9 = (*(code *)PTR_close_00036878)(*param_2);
        if (iVar9 != 0) {
          puVar4 = (undefined4 *)(*(code *)PTR___errno_location_00036990)();
          uVar5 = (*(code *)PTR_strerror_000367a8)(*puVar4);
          (*(code *)PTR_lib2sp_log_00036798)(param_1,4,PTR_LAB_00036774 + 0x32dc,auStack_103c,uVar5)
          ;
        }
        *param_2 = -1;
        *(undefined1 *)(param_2 + 4) = 0;
        param_2[3] = 0;
        param_2[2] = 0;
        do {
          iVar9 = (*(code *)PTR_unlink_00036844)(auStack_103c);
          if (iVar9 == 0) {
            return;
          }
          piVar6 = (int *)(*(code *)PTR___errno_location_00036990)();
        } while (*piVar6 == 4);
        uVar5 = (*(code *)PTR_strerror_000367a8)();
        (*(code *)PTR_lib2sp_log_00036798)(param_1,4,PTR_LAB_00036774 + 0x3bb8,auStack_103c,uVar5);
        return;
      }
      if (*(int *)(param_1 + 0x608) != 0) goto LAB_0001a840;
      local_1040 = local_1040 + iVar10;
    }
    else {
      uVar8 = (*(code *)PTR_write_00036888)(iVar9,param_5 + iVar10);
      if ((int)uVar8 < 0) {
        piVar6 = (int *)(*(code *)PTR___errno_location_00036990)();
        if (*piVar6 != 4) {
          if (*piVar6 != 0x1c) {
            uVar5 = *(undefined4 *)(param_3 + 8);
            local_30 = param_2[2];
            local_2c = param_2[3];
            (*(code *)PTR_strerror_000367a8)();
            (*(code *)PTR_lib2sp_set_error_0003683c)
                      (param_1,8,PTR_LAB_00036774 + 0x3b54,uVar5,param_4);
            goto LAB_0001a768;
          }
          (*(code *)PTR_lib2sp_log_00036798)
                    (param_1,4,PTR_LAB_00036774 + 0x3b2c,auStack_103c,param_2[2],param_2[3]);
          (*(code *)PTR_lib2sp_handle_no_space_00036858)(param_1,auStack_103c);
          if (*(int *)(param_1 + 8) != 0) goto LAB_0001a768;
          if (*(int *)(param_1 + 0x608) != 0) {
LAB_0001a840:
            (*(code *)PTR_lseek64_000368f4)(iVar9);
            (*(code *)PTR_ftruncate64_00036794)(iVar9);
            puVar1 = PTR_memcpy_00036978;
            *(longlong *)(param_2 + 2) = lVar11;
            param_2[7] = local_38;
            param_2[8] = local_34;
            (*(code *)puVar1)(param_2 + 9,auStack_1044,4);
            return;
          }
        }
      }
      else if (uVar8 != 0) {
        uVar2 = uVar8 + param_2[3];
        iVar3 = (uint)(uVar2 < uVar8) + ((int)uVar8 >> 0x1f) + param_2[2];
        iVar10 = iVar10 + uVar8;
        param_2[2] = iVar3;
        param_2[3] = uVar2;
        if (((param_2[1] & 0xf000U) == 0x8000) && (param_2[5] == 0x2f)) {
          iVar7 = param_2[7] - uVar8;
          param_2[7] = iVar7;
          puVar1 = PTR_lseek64_000368f4;
          if (iVar7 < 0) {
            (*(code *)PTR_printf_000367a4)(PTR_LAB_00036774 + 0x3b7c);
            (*(code *)PTR_lib2sp_set_error_0003683c)
                      (param_1,0xb,PTR_LAB_00036774 + 0x3b90,*(undefined4 *)(param_3 + 8),param_4,
                       param_2[7]);
            goto LAB_0001a768;
          }
          if (iVar7 == 0) {
            iVar7 = param_2[6];
            uVar8 = uVar2 + iVar7;
            param_2[2] = (uint)(uVar8 - 1 < uVar8) +
                         (uint)(uVar8 < uVar2) + iVar3 + (iVar7 >> 0x1f) + -1 & -iVar7 >> 0x1f;
            param_2[3] = uVar8 - 1 & -iVar7;
            (*(code *)puVar1)(iVar9);
            param_2[7] = -1;
            param_2[8] = 0;
            *(undefined1 *)(param_2 + 9) = 0;
            *(undefined1 *)((int)param_2 + 0x25) = 0;
            *(undefined1 *)((int)param_2 + 0x26) = 0;
            *(undefined1 *)((int)param_2 + 0x27) = 0;
          }
        }
      }
    }
  } while( true );
}


