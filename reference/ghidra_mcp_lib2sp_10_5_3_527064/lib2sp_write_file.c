
void lib2sp_write_file(int param_1,int *param_2,int param_3,undefined4 param_4,int param_5,
                      int param_6)

{
  undefined1 uVar1;
  undefined1 uVar2;
  undefined1 uVar3;
  undefined *puVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  undefined4 *puVar8;
  undefined4 uVar9;
  int *piVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  int iVar14;
  int iVar15;
  longlong lVar16;
  int local_1060;
  undefined1 auStack_105c [4];
  uint local_1058;
  undefined1 auStack_1054 [4100];
  uint *local_50;
  undefined1 *local_4c;
  undefined1 *local_48;
  undefined1 *local_44;
  undefined1 *local_40;
  int local_3c;
  int local_38;
  int *local_34;
  uint local_30;
  int local_2c;
  
  if (*(char *)(param_2 + 4) != '\0') {
    return;
  }
  iVar15 = *param_2;
  if (iVar15 < 0) {
    (*(code *)PTR_lib2sp_set_error_000344f4)(param_1,0xb,PTR_LAB_00034444 + 0x1c98);
    return;
  }
  (*(code *)PTR_snprintf_000345ac)
            (auStack_1054,0x1002,PTR_LAB_00034444 + 0x1460,*(undefined4 *)(param_3 + 8),param_4);
  (*(code *)PTR_lib2sp_check_space_00034630)(param_1,auStack_1054,&local_1060);
  if (*(int *)(param_1 + 8) != 0) {
    return;
  }
  if (*(int *)(param_1 + 0x5c8) != 0) {
    return;
  }
  lVar16 = (*(code *)PTR_lseek64_0003459c)(iVar15);
  if (lVar16 == *(longlong *)(param_2 + 2)) {
    local_3c = param_2[8];
  }
  else if ((param_2[1] & 0xf000U) == 0x8000) {
    (*(code *)PTR_printf_00034470)
              (PTR_LAB_00034444 + 0x1cb0,0x8000,(int)((ulonglong)lVar16 >> 0x20),(int)lVar16,
               param_2[2],param_2[3]);
    (*(code *)PTR_lib2sp_log_00034464)(param_1,4,PTR_LAB_00034444 + 0x1cc8);
    local_3c = param_2[8];
  }
  else {
    local_3c = param_2[8];
  }
  local_38 = param_2[7];
  piVar10 = param_2 + 9;
  (*(code *)PTR_memcpy_00034610)(auStack_105c,piVar10,4);
  local_48 = (undefined1 *)((int)param_2 + 0x25);
  local_44 = (undefined1 *)((int)param_2 + 0x26);
  local_40 = (undefined1 *)((int)param_2 + 0x27);
  local_4c = auStack_1054;
  local_34 = &local_1060;
  local_50 = &local_1058;
  iVar14 = 0;
LAB_00017658:
  do {
    if (param_6 <= iVar14) {
      return;
    }
    uVar13 = param_6 - iVar14;
    if (((param_2[1] & 0xf000U) == 0x8000) && (param_2[5] == 0x2f)) {
      uVar5 = param_2[7];
      if ((int)uVar5 < 0) {
        local_30 = 4 - param_2[8];
        if ((int)uVar13 <= (int)local_30) {
          local_30 = uVar13;
        }
        (*(code *)PTR_memcpy_00034610)
                  ((undefined1 *)((int)piVar10 + param_2[8]),param_5 + iVar14,local_30);
        iVar6 = param_2[8];
        iVar14 = iVar14 + local_30;
        param_2[8] = local_30 + iVar6;
        if (3 < local_30 + iVar6) {
          uVar1 = *local_44;
          uVar2 = *(undefined1 *)(param_2 + 9);
          uVar3 = *local_48;
          *(undefined1 *)((int)local_50 + 3) = *local_40;
          *(undefined1 *)local_50 = uVar2;
          *(undefined1 *)((int)local_50 + 1) = uVar3;
          *(undefined1 *)((int)local_50 + 2) = uVar1;
          if ((uint)param_2[6] < local_1058) {
            (*(code *)PTR_printf_00034470)(PTR_LAB_00034444 + 0x1cec);
            (*(code *)PTR_lib2sp_set_error_000344f4)
                      (param_1,8,PTR_LAB_00034444 + 0x1d00,*(undefined4 *)(param_3 + 8),param_4,
                       local_1058,param_2[6]);
            goto LAB_00017670;
          }
          param_2[7] = local_1058;
        }
        goto LAB_00017658;
      }
      if ((int)uVar5 < (int)uVar13) {
        uVar13 = uVar5;
      }
    }
    if ((uint)(local_1060 - iVar14) < uVar13) {
      uVar13 = local_1060 - iVar14;
    }
    if ((int)uVar13 < 1) {
      (*(code *)PTR_lib2sp_check_space_00034630)(param_1,local_4c,local_34);
      if (*(int *)(param_1 + 8) != 0) {
LAB_00017670:
        iVar15 = (*(code *)PTR_close_00034528)(*param_2);
        if (iVar15 != 0) {
          puVar8 = (undefined4 *)(*(code *)PTR___errno_location_00034624)();
          uVar9 = (*(code *)PTR_strerror_00034474)(*puVar8);
          (*(code *)PTR_lib2sp_log_00034464)(param_1,4,PTR_LAB_00034444 + 0x175c,auStack_1054,uVar9)
          ;
        }
        *param_2 = -1;
        param_2[3] = 0;
        param_2[2] = 0;
        *(undefined1 *)(param_2 + 4) = 0;
        do {
          iVar15 = (*(code *)PTR_unlink_000344fc)(auStack_1054);
          if (iVar15 == 0) {
            return;
          }
          piVar10 = (int *)(*(code *)PTR___errno_location_00034624)();
        } while (*piVar10 == 4);
        uVar9 = (*(code *)PTR_strerror_00034474)();
        (*(code *)PTR_lib2sp_log_00034464)(param_1,4,PTR_LAB_00034444 + 0x1dc4,auStack_1054,uVar9);
        return;
      }
      if (*(int *)(param_1 + 0x5c8) != 0) goto LAB_0001774c;
      local_1060 = local_1060 + iVar14;
    }
    else {
      uVar13 = (*(code *)PTR_write_00034538)(iVar15,param_5 + iVar14);
      if ((int)uVar13 < 0) {
        piVar7 = (int *)(*(code *)PTR___errno_location_00034624)();
        if (*piVar7 != 4) {
          if (*piVar7 != 0x1c) {
            uVar9 = *(undefined4 *)(param_3 + 8);
            local_30 = param_2[2];
            local_2c = param_2[3];
            (*(code *)PTR_strerror_00034474)();
            (*(code *)PTR_lib2sp_set_error_000344f4)
                      (param_1,8,PTR_LAB_00034444 + 0x1d60,uVar9,param_4);
            goto LAB_00017670;
          }
          (*(code *)PTR_lib2sp_log_00034464)
                    (param_1,4,PTR_LAB_00034444 + 0x1d38,local_4c,param_2[2],param_2[3]);
          (*(code *)PTR_lib2sp_handle_no_space_00034508)(param_1,local_4c);
          if (*(int *)(param_1 + 8) != 0) goto LAB_00017670;
          if (*(int *)(param_1 + 0x5c8) != 0) {
LAB_0001774c:
            (*(code *)PTR_lseek64_0003459c)(iVar15);
            (*(code *)PTR_ftruncate64_00034460)(iVar15);
            puVar4 = PTR_memcpy_00034610;
            param_2[8] = local_3c;
            param_2[7] = local_38;
            *(longlong *)(param_2 + 2) = lVar16;
            (*(code *)puVar4)(piVar10,auStack_105c,4);
            return;
          }
        }
      }
      else if (uVar13 != 0) {
        uVar5 = uVar13 + param_2[3];
        iVar6 = (uint)(uVar5 < uVar13) + ((int)uVar13 >> 0x1f) + param_2[2];
        iVar14 = iVar14 + uVar13;
        param_2[2] = iVar6;
        param_2[3] = uVar5;
        if (((param_2[1] & 0xf000U) == 0x8000) && (param_2[5] == 0x2f)) {
          iVar11 = param_2[7] - uVar13;
          param_2[7] = iVar11;
          puVar4 = PTR_lseek64_0003459c;
          if (iVar11 < 0) {
            (*(code *)PTR_printf_00034470)(PTR_LAB_00034444 + 0x1d88);
            (*(code *)PTR_lib2sp_set_error_000344f4)
                      (param_1,0xb,PTR_LAB_00034444 + 0x1d9c,*(undefined4 *)(param_3 + 8),param_4,
                       param_2[7]);
            goto LAB_00017670;
          }
          if (iVar11 == 0) {
            uVar13 = param_2[6];
            uVar12 = uVar13 - 1;
            param_2[2] = (uint)(uVar12 + uVar5 < uVar12) +
                         (uint)(uVar12 < uVar13) + ((int)uVar13 >> 0x1f) + -1 + iVar6 &
                         (int)-uVar13 >> 0x1f;
            param_2[3] = uVar12 + uVar5 & -uVar13;
            (*(code *)puVar4)(iVar15);
            param_2[7] = -1;
            param_2[8] = 0;
            *(undefined1 *)piVar10 = 0;
            *(undefined1 *)((int)param_2 + 0x25) = 0;
            *(undefined1 *)((int)param_2 + 0x26) = 0;
            *(undefined1 *)((int)param_2 + 0x27) = 0;
          }
        }
      }
    }
  } while( true );
}


