
int pkgman_run_installer(int param_1)

{
  undefined *puVar1;
  undefined4 uVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  undefined *puVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  undefined4 uVar17;
  undefined1 auStack_78 [4];
  undefined4 uStack_74;
  int iStack_70;
  int iStack_6c;
  int iStack_68;
  int iStack_64;
  int iStack_60;
  int iStack_5c;
  int iStack_58;
  int iStack_54;
  int iStack_50;
  uint uStack_4c;
  int iStack_48;
  int iStack_44;
  int iStack_40;
  uint uStack_3c;
  int iStack_38;
  int iStack_34;
  uint uStack_30;
  int iStack_2c;
  
  iVar12 = *(int *)(param_1 + 0x2c);
  uVar17 = *(undefined4 *)(param_1 + 0x28);
  uStack_30 = *(uint *)(iVar12 + 0x1d8);
  uStack_74 = 0;
  iStack_2c = (*(code *)PTR_getppid_00447410)();
  uVar2 = (*(code *)PTR_getpid_004477a4)();
  pkg_log_trace(uStack_30,&UNK_00434538,iStack_2c,uVar2);
  iVar3 = (*(code *)PTR_ar_ioctx_create_004474e4)(&uStack_74);
  if (iVar3 == 0) {
    iVar3 = (*(code *)PTR_cm_db_connect_004477c8)(uStack_74,&UNK_0043138c,iVar12 + 0x1e8);
    if (iVar3 == 0) {
      iVar13 = *(int *)(iVar12 + 0x1e8);
      iVar16 = (*(code *)PTR_malloc_004475f4)(16000);
      if (iVar16 == 0) {
        (*(code *)PTR_syslog_004477f0)(3,&UNK_004345a4);
        iVar14 = -1;
        iVar3 = 0xc;
        goto code_r0x00421b14;
      }
      iVar14 = (*(code *)PTR_open64_00447720)(&UNK_004342ec,0);
      if (-1 < iVar14) {
        iVar3 = (*(code *)PTR_pthread_mutex_lock_00447690)(param_1);
        iVar8 = iVar3;
        if (iVar3 == 0) {
          pkg_status_set_active(*(undefined4 *)(param_1 + 0x6c),1);
          pkg_status_set_active(*(undefined4 *)(param_1 + 0x70),1);
          *(undefined4 *)(param_1 + 0x5c) = 0;
          *(undefined4 *)(param_1 + 0x58) = 0;
          iStack_38 = 1;
          uStack_3c = 0;
          iStack_40 = 0;
code_r0x00420fa0:
          do {
            if (*(int *)(param_1 + 100) == 0) {
              if (*(char *)(param_1 + 0x68) == '\0') {
                if (*(int *)(param_1 + 0x40) < 1) {
                  if ((*(int *)(param_1 + 0x40) == 0) && (*(int *)(param_1 + 0x44) != 0)) {
                    iVar8 = *(int *)(param_1 + 100);
                  }
                  else {
                    pkg_status_set_inactive(*(undefined4 *)(param_1 + 0x6c),1);
                    pkg_status_set_inactive(*(undefined4 *)(param_1 + 0x70),1);
                    while (*(int *)(param_1 + 100) == 0) {
                      if (*(char *)(param_1 + 0x68) != '\0') {
                        uVar2 = *(undefined4 *)(param_1 + 0x6c);
                        goto code_r0x00421058;
                      }
                      if (0 < *(int *)(param_1 + 0x40)) {
                        uVar2 = *(undefined4 *)(param_1 + 0x6c);
                        goto code_r0x00421058;
                      }
                      if ((*(int *)(param_1 + 0x40) == 0) && (*(int *)(param_1 + 0x44) != 0)) break;
                      (*(code *)PTR_pthread_cond_wait_004475cc)(param_1 + 0x18,param_1);
                    }
                    uVar2 = *(undefined4 *)(param_1 + 0x6c);
code_r0x00421058:
                    pkg_status_set_active(uVar2,1);
                    pkg_status_set_active(*(undefined4 *)(param_1 + 0x70),1);
                    iVar8 = *(int *)(param_1 + 100);
                  }
                }
                else {
                  iVar8 = *(int *)(param_1 + 100);
                }
              }
              else {
                iVar8 = *(int *)(param_1 + 100);
              }
            }
            else {
              iVar8 = *(int *)(param_1 + 100);
            }
            if (iVar8 != 0) {
              uVar2 = *(undefined4 *)(iVar12 + 0x1d8);
              puVar11 = &UNK_004345e4;
code_r0x0042151c:
              pkg_log_error(uVar2,puVar11,__FUNCTION___24443);
              goto code_r0x00421b50;
            }
            iVar3 = *(int *)(param_1 + 0x40);
            uVar9 = *(uint *)(param_1 + 0x44);
            if ((*(char *)(param_1 + 0x68) != '\0') && (iVar3 < 1)) {
              if (iVar3 == 0) {
                if (uVar9 != 0) goto code_r0x00421124;
                uVar2 = *(undefined4 *)(iVar12 + 0x1d8);
              }
              else {
                uVar2 = *(undefined4 *)(iVar12 + 0x1d8);
              }
              pkg_log_info(uVar2,&UNK_00434600,__FUNCTION___24443,1,iVar3,uVar9);
              (*(code *)PTR_pthread_mutex_unlock_00447764)(param_1);
              iVar3 = (*(code *)PTR_lib2sp_finish_data_004477f4)(uVar17);
              if (iVar3 != 0) {
                uVar2 = *(undefined4 *)(iVar12 + 0x1d8);
                puVar11 = &UNK_004348cc;
code_r0x00421970:
                pkg_log_error(uVar2,puVar11,__FUNCTION___24443,iVar3);
                goto code_r0x00421b14;
              }
              pkg_status_set_inactive(*(undefined4 *)(param_1 + 0x6c),1);
              pkg_status_set_inactive(*(undefined4 *)(param_1 + 0x70),1);
              iVar3 = (*(code *)PTR_pthread_mutex_lock_00447690)(param_1);
              puVar11 = PTR_lib2sp_is_dpi_state_done_004475c0;
              if (iVar3 != 0) {
                uVar2 = *(undefined4 *)(iVar12 + 0x1d8);
                goto code_r0x004219d0;
              }
              *(undefined1 *)(param_1 + 0x60) = 1;
              *(undefined1 *)(param_1 + 0x69) = 0;
              iVar3 = (*(code *)puVar11)(uVar17);
              if (iVar3 != 0) {
                *(uint *)(iVar12 + 8) = *(uint *)(iVar12 + 8) | 1;
              }
              pkg_log_info(*(undefined4 *)(iVar12 + 0x1d8),&UNK_004348f8,__FUNCTION___24443,
                           *(undefined4 *)(iVar12 + 8),*(undefined4 *)(iVar12 + 4));
              (*(code *)PTR_pthread_cond_broadcast_00447830)(param_1 + 0x18);
              auStack_78[0] = 0;
              (*(code *)PTR_write_004476a0)(*(undefined4 *)(param_1 + 0x24),auStack_78,1);
              (*(code *)PTR_pthread_mutex_unlock_00447764)(param_1);
              if (iVar13 != 0) {
                (*(code *)PTR_cm_db_disconnect_00447824)(iVar13);
                (*(code *)PTR_ar_ioctx_destroy_00447484)(uStack_74);
                *(undefined4 *)(iVar12 + 0x1e8) = 0;
              }
              (*(code *)PTR_close_00447498)(iVar14);
              (*(code *)PTR_free_004478d4)(iVar16);
              puVar11 = &UNK_00434910;
              pkg_log_info(*(undefined4 *)(iVar12 + 0x1d8));
              goto code_r0x00421c0c;
            }
code_r0x00421124:
            if (iVar3 < 1) {
              if (iVar3 == 0) {
                if (16000 < uVar9) goto code_r0x00421140;
                uStack_30 = *(uint *)(param_1 + 0x3c);
              }
              else {
                uStack_30 = *(uint *)(param_1 + 0x3c);
              }
            }
            else {
code_r0x00421140:
              uVar9 = 16000;
              iVar3 = 0;
              uStack_30 = *(uint *)(param_1 + 0x3c);
            }
            iStack_2c = *(int *)(param_1 + 0x38);
            iVar3 = (uint)(uStack_30 + uVar9 < uStack_30) + iStack_2c + iVar3;
            if ((*(int *)(param_1 + 0x48) < iVar3) ||
               ((iVar3 == *(int *)(param_1 + 0x48) &&
                (*(uint *)(param_1 + 0x4c) < uStack_30 + uVar9)))) {
              uVar9 = *(uint *)(param_1 + 0x4c) - uStack_30;
            }
            (*(code *)PTR_pthread_mutex_unlock_00447764)(param_1);
            uVar2 = 0;
            (*(code *)PTR_lseek64_00447544)(iVar14);
            uVar9 = (*(code *)PTR_read_00447708)(iVar14,iVar16,uVar9);
            piVar4 = (int *)(*(code *)PTR___errno_location_004476c0)();
            iVar3 = *piVar4;
            iVar8 = (*(code *)PTR_pthread_mutex_lock_00447690)(param_1);
            if (iVar8 != 0) {
              uVar17 = *(undefined4 *)(iVar12 + 0x1d8);
              uVar2 = (*(code *)PTR_strerror_00447428)(iVar8);
              pkg_log_error(uVar17,&UNK_0043462c,__FUNCTION___24443,uVar2);
              uVar2 = (*(code *)PTR_strerror_00447428)(iVar8);
              (*(code *)PTR_syslog_004477f0)(3,&UNK_00433fa4,uVar2);
              iVar3 = iVar8;
              goto code_r0x00421b14;
            }
            if (-1 < (int)uVar9) {
              if (uVar9 != 0) {
                uVar10 = *(uint *)(param_1 + 0x44);
                uVar5 = uVar10 - uVar9;
                *(uint *)(param_1 + 0x44) = uVar5;
                uVar6 = uVar9 + *(int *)(param_1 + 0x3c);
                *(uint *)(param_1 + 0x40) =
                     (*(int *)(param_1 + 0x40) - ((int)uVar9 >> 0x1f)) - (uint)(uVar10 < uVar5);
                iVar3 = (uint)(uVar6 < uVar9) + ((int)uVar9 >> 0x1f) + *(int *)(param_1 + 0x38);
                *(int *)(param_1 + 0x38) = iVar3;
                *(uint *)(param_1 + 0x3c) = uVar6;
                if ((*(int *)(param_1 + 0x48) <= iVar3) &&
                   ((*(int *)(param_1 + 0x48) != iVar3 || (*(uint *)(param_1 + 0x4c) <= uVar6)))) {
                  *(undefined4 *)(param_1 + 0x3c) = 0;
                  *(undefined4 *)(param_1 + 0x38) = 0;
                }
                iStack_34 = param_1 + 0x18;
                (*(code *)PTR_pthread_cond_broadcast_00447830)(iStack_34);
                iVar15 = 0;
                (*(code *)PTR_pthread_mutex_unlock_00447764)(param_1);
code_r0x00421390:
                iVar3 = (*(code *)PTR_lib2sp_get_state_004478ac)(uVar17,&iStack_6c);
                if (iVar3 != 0) {
                  pkg_log_error(*(undefined4 *)(iVar12 + 0x1d8),&UNK_004346c4,__FUNCTION___24443,
                                iVar3);
                  puVar11 = &UNK_004346f4;
                  iVar8 = iVar3;
                  goto code_r0x00421a04;
                }
                if ((iStack_6c != 4) || (iStack_38 == 0)) goto code_r0x004216d8;
                pkg_log_info(*(undefined4 *)(iVar12 + 0x1d8),&UNK_00434710,__FUNCTION___24443);
                (*(code *)PTR_syslog_004477f0)(6,&UNK_00434714);
                iVar8 = (*(code *)PTR_pthread_mutex_lock_00447690)(param_1);
                if (iVar8 == 0) {
                  uVar5 = uVar9 - iVar15;
                  iVar3 = (int)(uVar9 - iVar15) >> 0x1f;
                  do {
                    if (*(int *)(param_1 + 100) != 0) {
                      uVar2 = *(undefined4 *)(iVar12 + 0x1d8);
                      puVar11 = &UNK_0043477c;
                      iVar3 = iVar8;
                      goto code_r0x0042151c;
                    }
                    iVar7 = *(int *)(param_1 + 0x40);
                    uVar6 = *(uint *)(param_1 + 0x44);
                    if (*(char *)(param_1 + 0x68) != '\0') {
                      uVar5 = uVar9 - iVar15;
                      uVar6 = uVar5 + uVar6;
                      iVar3 = (uint)(uVar6 + uStack_3c < uVar6) +
                              (uint)(uVar6 < uVar5) + ((int)uVar5 >> 0x1f) + iVar7 + iStack_40;
                      if (*(int *)(param_1 + 0x50) <= iVar3) {
                        if (*(int *)(param_1 + 0x50) != iVar3) {
                          iVar3 = *(int *)(param_1 + 0x44);
                          goto code_r0x00421658;
                        }
                        if (*(uint *)(param_1 + 0x54) <= uVar6 + uStack_3c) {
                          iVar3 = *(int *)(param_1 + 0x44);
                          goto code_r0x00421658;
                        }
                      }
                      (*(code *)PTR_syslog_004477f0)(3,&UNK_00434798);
                      pkg_log_error(*(undefined4 *)(iVar12 + 0x1d8),&UNK_004347ac,__FUNCTION___24443
                                    ,0xca);
                      goto code_r0x00421650;
                    }
                    if (*(int *)(param_1 + 0x48) <= iVar7) {
                      if (*(int *)(param_1 + 0x48) != iVar7) {
                        iVar3 = *(int *)(param_1 + 0x44);
                        goto code_r0x00421658;
                      }
                      if (*(uint *)(param_1 + 0x4c) <= uVar6) {
                        iVar3 = *(int *)(param_1 + 0x44);
                        goto code_r0x00421658;
                      }
                    }
                    uVar10 = uVar6 + uVar5;
                    iVar7 = (uint)(uVar10 + uStack_3c < uVar10) +
                            (uint)(uVar10 < uVar6) + iVar7 + iVar3 + iStack_40;
                    if (iVar7 < *(int *)(param_1 + 0x50)) {
                      uVar2 = *(undefined4 *)(param_1 + 0x6c);
                    }
                    else {
                      if (*(int *)(param_1 + 0x50) != iVar7) {
                        iVar3 = *(int *)(param_1 + 0x44);
                        goto code_r0x00421658;
                      }
                      if (*(uint *)(param_1 + 0x54) <= uVar10 + uStack_3c) goto code_r0x004215b4;
                      uVar2 = *(undefined4 *)(param_1 + 0x6c);
                    }
                    uStack_30 = uVar5;
                    iStack_2c = iVar3;
                    pkg_status_set_inactive(uVar2,1);
                    pkg_status_set_inactive(*(undefined4 *)(param_1 + 0x70),1);
                    (*(code *)PTR_pthread_cond_wait_004475cc)(iStack_34,param_1);
                    pkg_status_set_active(*(undefined4 *)(param_1 + 0x6c),1);
                    pkg_status_set_active(*(undefined4 *)(param_1 + 0x70),1);
                    uVar5 = uStack_30;
                    iVar3 = iStack_2c;
                  } while( true );
                }
                uVar2 = *(undefined4 *)(iVar12 + 0x1d8);
                iVar3 = (*(code *)PTR_strerror_00447428)(iVar8);
                puVar11 = &UNK_00434750;
                goto code_r0x004219d4;
              }
              pkg_log_error(*(undefined4 *)(iVar12 + 0x1d8),&UNK_0043467c,__FUNCTION___24443,iVar3,
                            uVar2);
              (*(code *)PTR_syslog_004477f0)(3,&UNK_004346ac);
code_r0x00421650:
              iVar3 = 0xca;
              goto code_r0x00421b50;
            }
            if (iVar3 != 4) {
              pkg_log_error(*(undefined4 *)(iVar12 + 0x1d8),&UNK_0043465c,__FUNCTION___24443,uVar9,
                            iVar3);
              goto code_r0x00421b50;
            }
          } while( true );
        }
        goto code_r0x004219e4;
      }
      piVar4 = (int *)(*(code *)PTR___errno_location_004476c0)();
      iVar8 = *piVar4;
      iVar3 = (*(code *)PTR_strerror_00447428)(iVar8);
      puVar11 = &UNK_004345c4;
      goto code_r0x00421a04;
    }
    (*(code *)PTR_ar_ioctx_destroy_00447484)(uStack_74);
    uVar2 = (*(code *)PTR_strerror_00447428)(iVar3);
    puVar11 = &UNK_00434580;
  }
  else {
    uVar2 = (*(code *)PTR_strerror_00447428)(iVar3);
    puVar11 = &UNK_00434568;
  }
  (*(code *)PTR_syslog_004477f0)(3,puVar11,uVar2);
  iVar13 = 0;
  iVar14 = -1;
  iVar16 = 0;
  goto code_r0x00421b14;
code_r0x004215b4:
  iVar3 = *(int *)(param_1 + 0x44);
code_r0x00421658:
  uVar5 = uVar9 - iVar15;
  (*(code *)PTR_syslog_004477f0)
            (6,&UNK_004347d4,
             (uint)(uVar5 + iVar3 < uVar5) + ((int)uVar5 >> 0x1f) + *(int *)(param_1 + 0x40),
             uVar5 + iVar3,iStack_40,uStack_3c);
  puVar11 = PTR_pthread_mutex_unlock_00447764;
  *(undefined1 *)(param_1 + 0x6a) = 1;
  (*(code *)puVar11)(param_1);
  pkg_log_info(*(undefined4 *)(iVar12 + 0x1d8),&UNK_00434824);
  iStack_38 = 0;
code_r0x004216d8:
  iVar3 = (*(code *)PTR_lib2sp_get_verify_status_004478f8)(uVar17,&iStack_58,&iStack_48);
  if (iVar3 != 0) {
    pkg_log_info(*(undefined4 *)(iVar12 + 0x1d8),&UNK_00434844,__FUNCTION___24443,iVar3);
    iStack_54 = 0;
    iStack_58 = 0;
    iStack_44 = 0;
    iStack_48 = 0;
  }
  (*(code *)PTR_clock_gettime_00447554)(1,&iStack_60);
  iVar3 = (*(code *)PTR_lib2sp_install_data_0044785c)
                    (uVar17,iVar16 + iVar15,uVar9 - iVar15,&iStack_70);
  if (iVar3 != 0) {
    uVar2 = *(undefined4 *)(iVar12 + 0x1d8);
    puVar11 = &UNK_00434870;
    goto code_r0x00421970;
  }
  if (iStack_58 != 0 || iStack_54 != 0) {
    iVar3 = (*(code *)PTR_lib2sp_get_verify_status_004478f8)(uVar17,&iStack_58,&iStack_50);
    uVar5 = uStack_4c - iStack_44;
    iStack_50 = (iStack_50 - iStack_48) - (uint)(uStack_4c < uVar5);
    uStack_4c = uVar5;
    if ((iVar3 == 0) && (iStack_50 != 0 || uVar5 != 0)) {
      (*(code *)PTR_clock_gettime_00447554)(1,&iStack_68);
      iStack_68 = iStack_68 - iStack_60;
      iStack_64 = iStack_64 - iStack_5c;
      if (iStack_64 < 0) {
        iStack_68 = iStack_68 + -1;
        iStack_64 = iStack_64 + 1000000000;
      }
      pkg_status_update2(iVar12,iVar13,*(undefined4 *)(param_1 + 0x6c),4,iStack_50,uStack_4c,
                         &iStack_68);
      pkg_status_update2(iVar12,iVar13,*(undefined4 *)(param_1 + 0x6c),4,iStack_50,uStack_4c,
                         &iStack_68);
    }
  }
  pkg_status_update(iVar12,iVar13,*(undefined4 *)(param_1 + 0x6c),1,iStack_70 >> 0x1f,iStack_70);
  pkg_status_update(iVar12,iVar13,*(undefined4 *)(param_1 + 0x70),1,iStack_70 >> 0x1f,iStack_70);
  iVar15 = iVar15 + iStack_70;
  uVar5 = uStack_3c + iStack_70;
  iStack_40 = (uint)(uVar5 < uStack_3c) + iStack_40 + (iStack_70 >> 0x1f);
  *(int *)(param_1 + 0x58) = iStack_40;
  *(uint *)(param_1 + 0x5c) = uVar5;
  uStack_3c = uVar5;
  if ((int)uVar9 <= iVar15) goto code_r0x00421930;
  goto code_r0x00421390;
code_r0x00421930:
  iVar3 = (*(code *)PTR_pthread_mutex_lock_00447690)(param_1);
  if (iVar3 != 0) goto code_r0x00421948;
  goto code_r0x00420fa0;
code_r0x00421948:
  uVar2 = *(undefined4 *)(iVar12 + 0x1d8);
code_r0x004219d0:
  puVar11 = &UNK_004348a0;
  iVar8 = iVar3;
code_r0x004219d4:
  pkg_log_error(uVar2,puVar11,__FUNCTION___24443,iVar3);
code_r0x004219e4:
  iVar3 = (*(code *)PTR_strerror_00447428)(iVar8);
  puVar11 = &UNK_00433fa4;
code_r0x00421a04:
  (*(code *)PTR_syslog_004477f0)(3,puVar11,iVar3);
  iVar3 = iVar8;
code_r0x00421b14:
  iVar8 = (*(code *)PTR_pthread_mutex_lock_00447690)(param_1);
  if (iVar8 != 0) {
    uVar2 = (*(code *)PTR_strerror_00447428)(iVar8);
    (*(code *)PTR_syslog_004477f0)(3,&UNK_00433fa4,uVar2);
  }
code_r0x00421b50:
  if (*(int *)(param_1 + 100) == 0) {
    *(int *)(param_1 + 100) = iVar3;
  }
  puVar11 = PTR_pthread_cond_broadcast_00447830;
  *(undefined1 *)(param_1 + 0x69) = 0;
  (*(code *)puVar11)(param_1 + 0x18);
  auStack_78[0] = 0;
  (*(code *)PTR_write_004476a0)(*(undefined4 *)(param_1 + 0x24),auStack_78,1);
  (*(code *)PTR_pthread_mutex_unlock_00447764)(param_1);
  if (iVar13 != 0) {
    (*(code *)PTR_cm_db_disconnect_00447824)(iVar13);
    (*(code *)PTR_ar_ioctx_destroy_00447484)(uStack_74);
    *(undefined4 *)(iVar12 + 0x1e8) = 0;
  }
  if (-1 < iVar14) {
    (*(code *)PTR_close_00447498)(iVar14);
  }
  if (iVar16 != 0) {
    (*(code *)PTR_free_004478d4)(iVar16);
  }
  puVar11 = &UNK_0043493c;
  pkg_log_error(*(undefined4 *)(iVar12 + 0x1d8),&UNK_0043493c,iVar3,*(undefined4 *)(param_1 + 100));
code_r0x00421c0c:
  uVar2 = 0;
  (*(code *)PTR_pthread_exit_004477c4)(0);
  if ((*(int *)(puVar11 + 0x68) == 0) && (*(int *)(puVar11 + 0x6c) < 0)) {
    iVar3 = pkg_util_httpc_create();
    if ((iVar3 == 0) &&
       (iVar3 = pkg_util_httpc_req_create
                          (uVar2,*(undefined4 *)(puVar11 + 0x14),*(undefined4 *)(puVar11 + 0x18),
                           puVar11 + 0x68), puVar1 = PTR_httpc_destroy_00447884, iVar3 != 0)) {
      puVar11[0x93] = 1;
      (*(code *)puVar1)(*(undefined4 *)(puVar11 + 0x68));
      *(undefined4 *)(puVar11 + 0x68) = 0;
    }
  }
  else {
    (*(code *)PTR_snprintf_004477b0)
              (*(undefined4 *)(puVar11 + 0x14),*(undefined4 *)(puVar11 + 0x18),&UNK_00434988);
    iVar3 = 0x10;
  }
  return iVar3;
}


