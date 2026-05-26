
int pkgman_extract_pkg(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  undefined *puVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  code *pcVar8;
  undefined4 uStack_1080;
  undefined4 uStack_107c;
  undefined4 uStack_1078;
  undefined1 auStack_1074 [63];
  char acStack_1035 [4101];
  undefined4 uStack_30;
  
  (*(code *)PTR_memset_0044771c)(acStack_1035 + 1,0,0x1001);
  (*(code *)PTR_memset_0044771c)(auStack_1074,0,0x40);
  iVar5 = 0x16;
  if (((*(int *)(*(int *)(param_3 + 0x24) + 0x38) == 1) &&
      (iVar5 = 2, (*(uint *)(param_3 + 0x44) & 0x10) != 0)) &&
     (iVar5 = pkg_util_pkg_get_base(acStack_1035 + 1,0x1001), iVar5 == 0)) {
    uVar1 = (*(code *)PTR_strlen_00447908)(acStack_1035 + 1);
    uVar7 = uVar1;
    if (acStack_1035[uVar1] != '/') {
      if (0xfff < uVar1) {
        return 0x4e;
      }
      acStack_1035[uVar1 + 1] = '/';
      uVar7 = uVar1 + 1;
      acStack_1035[uVar1 + 2] = '\0';
    }
    iVar5 = (*(code *)PTR__cm_tran_begin_004476f0)(param_2,2,&uStack_1080,&UNK_00433230,0x2da);
    if (iVar5 == 0) {
      iVar5 = (*(code *)PTR__cm_tran_lockn_00447644)(uStack_1080,&UNK_00433230,0x2e0,2,1,0x37);
      if (iVar5 != 0) {
        (*(code *)PTR__cm_tran_abort_0044752c)(uStack_1080,&UNK_00433230,0x2e2);
        pkg_log_error(*(undefined4 *)(param_1 + 0x1d8),&UNK_00433278);
        return iVar5;
      }
      iVar5 = (*(code *)PTR_cm_tran_getn_str_00447728)
                        (uStack_1080,acStack_1035 + uVar7 + 1,0x1001 - uVar7,4,1,0x37,
                         *(undefined4 *)(param_3 + 0x40),2);
      if (iVar5 == 0) {
        iVar5 = pkg_util_active_publish(param_1,uStack_1080,param_3);
        if (iVar5 != 0) {
          uStack_30 = *(undefined4 *)(param_3 + 0x40);
          uVar6 = *(undefined4 *)(param_1 + 0x1d8);
          uVar2 = (*(code *)PTR_strerror_00447428)(iVar5);
          pkg_log_warning(uVar6,&UNK_004332b8,uStack_30,uVar2);
        }
        iVar5 = (*(code *)PTR_lib2sp_create_context_004477a0)(&uStack_107c);
        if (iVar5 == 0) {
          iVar5 = pkg_util_set_2sp_sys_info(param_1,uStack_1080,uStack_107c);
          if (iVar5 == 0) {
            (*(code *)PTR__cm_tran_commit_004477d0)(uStack_1080,&UNK_00433230,0x302);
            if ((*(int *)(param_1 + 4) < 0) &&
               (iVar5 = pkg_log_getlogpath(*(undefined4 *)(param_1 + 0x1d8)), iVar5 != 0)) {
              (*(code *)PTR_lib2sp_set_log_file_00447938)(uStack_107c,iVar5);
            }
            pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_004332ec,acStack_1035 + 1);
            iVar5 = (*(code *)PTR_lib2sp_simple_unpack_004474d0)(uStack_107c,acStack_1035 + 1);
            if (iVar5 == 0) {
              uStack_1078 = 0x40;
              iVar3 = (*(code *)PTR_lib2sp_get_version_004478fc)
                                (uStack_107c,auStack_1074,&uStack_1078);
              if (iVar3 == 0) {
                uVar2 = *(undefined4 *)(param_3 + 0x30);
                iVar3 = (*(code *)PTR_strcmp_00447778)(uVar2,auStack_1074);
                if (iVar3 != 0) {
                  pkg_log_warning(*(undefined4 *)(param_1 + 0x1d8),&UNK_00433380,
                                  *(undefined4 *)(*(int *)(param_3 + 0x24) + 0x44),
                                  *(undefined4 *)(param_3 + 0x28),uVar2,auStack_1074);
                  pkg_package_setversion(param_3,auStack_1074);
                  pkg_util_setversion(param_3,param_2);
                }
              }
              else {
                uVar6 = *(undefined4 *)(param_1 + 0x1d8);
                uVar2 = (*(code *)PTR_strerror_00447428)(iVar3);
                pkg_log_warning(uVar6,&UNK_00433350,uVar2);
              }
              pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_004333e0,
                           *(undefined4 *)(*(int *)(param_3 + 0x24) + 0x44),
                           *(undefined4 *)(param_3 + 0x28));
              iVar3 = (*(code *)PTR_lib2sp_get_uninstall_script_00447920)
                                (uStack_107c,acStack_1035 + 1,0x1001);
              if (iVar3 == 0) {
                iVar3 = pkg_package_setuninstall(param_3,acStack_1035 + 1);
                iVar5 = 0;
                if (iVar3 != 0) {
                  (*(code *)PTR_lib2sp_destroy_context_004473d8)(uStack_107c);
                  pkg_log_warning(*(undefined4 *)(param_1 + 0x1d8),&UNK_0043343c,
                                  *(undefined4 *)(*(int *)(param_3 + 0x24) + 0x44),
                                  *(undefined4 *)(param_3 + 0x28));
                  return 0;
                }
              }
              else {
                pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_00433404,
                             *(undefined4 *)(*(int *)(param_3 + 0x24) + 0x44),
                             *(undefined4 *)(param_3 + 0x28));
              }
            }
            else {
              uVar6 = *(undefined4 *)(param_1 + 0x1d8);
              uVar2 = (*(code *)PTR_strerror_00447428)(iVar5);
              pkg_log_warning(uVar6,&UNK_00433318,uVar2);
            }
            (*(code *)PTR_lib2sp_destroy_context_004473d8)(uStack_107c);
            return iVar5;
          }
          (*(code *)PTR_lib2sp_destroy_context_004473d8)(uStack_107c);
          uVar2 = 0x2fe;
        }
        else {
          uVar2 = 0x2f7;
        }
      }
      else {
        uVar2 = 0x2eb;
      }
      puVar4 = &UNK_00433230;
      pcVar8 = (code *)PTR__cm_tran_abort_0044752c;
    }
    else {
      uVar6 = *(undefined4 *)(param_1 + 0x1d8);
      uVar2 = (*(code *)PTR_strerror_00447428)(iVar5);
      puVar4 = &UNK_00433240;
      uStack_1080 = uVar6;
      pcVar8 = (code *)PTR_pkg_log_error_00447194;
    }
    (*pcVar8)(uStack_1080,puVar4,uVar2);
  }
  return iVar5;
}


