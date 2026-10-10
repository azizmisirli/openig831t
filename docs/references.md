# Primary references and source scope

References are links, not redistributed vendor documents. A source applies only to its documented version, model and composition. Current web availability is separate from the pinned research record. **FAMILY_LEVEL_SOURCE_EVIDENCE** must not be promoted to a measurement of an exact candidate.

## DJI

- [DJI Cellular Dongle 2 User Guide v1.0](https://dl.djicdn.com/downloads/DJI_Air_3/AC/DJI_Cellular_Dongle_2_User_Guide_multi.pdf): manufacturer product specification; not a 5G replacement protocol.
- [Official Mobile SDK Android V5 repository](https://github.com/dji-sdk/Mobile-SDK-Android-V5).
- [Pinned LTEVM sample, commit a48aa4e7811d824c27abfa973f5655579bfb8a77](https://github.com/dji-sdk/Mobile-SDK-Android-V5/blob/a48aa4e7811d824c27abfa973f5655579bfb8a77/SampleCode-V5/android-sdk-v5-sample/src/main/java/dji/sampleV5/aircraft/models/LTEVM.kt): public API use; not proof of every private implementation or actual host acceptance.

## Fibocom and certification

- [Fibocom product reference](https://www.fibocom.com/en/SeriesProduct/info_itemid_121.html) and [official information center](https://infocenter.fibocom.com/): manufacturer resources; exact SKU/firmware applicability must be checked.
- [Fibocom FM190W-GL product page](https://www.fibocom.com/jp/products/5G-FM190W-GL.html): family product information, not a measured USB composition.
- [GCF IG831T certification reference 12730](https://www.globalcertificationforum.org/pub_product/12730.html): certification declaration, distinct from the specimen's measurements and DJI's specification list.

## Quectel

- [RM520N Series specification v1.4](https://www.quectel.com/content/uploads/2024/03/Quectel_RM520N_Series_5G_Module_Specification_V1.4.pdf): family specifications and variant qualifications.
- [UMTS/LTE/5G Linux USB Driver User Guide v3.2](https://www.quectel.com/content/uploads/2024/04/Quectel_UMTS_LTE_5G_Linux_USB_Driver_User_Guide_V3.2.pdf): documented compositions and driver paths; no exact-unit interoperability guarantee.
- [5G-M2 EVB kit](https://www.quectel.com/product/5g-m2-evb-kit/): listed RM520N-series carrier family. [Generic 5G EVB](https://www.quectel.com/product/5g-evb-kit/) is a different product family.

## Linux, USB and QMI

- [Linux v6.12 FunctionFS implementation](https://github.com/torvalds/linux/blob/v6.12/drivers/usb/gadget/function/f_fs.c) and [UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/usb/functionfs.h): patch baseline and userspace ABI.
- [Linux v6.12 FunctionFS documentation](https://github.com/torvalds/linux/blob/v6.12/Documentation/usb/functionfs.rst).
- [Linux v6.12 endpoint autoconfiguration](https://github.com/torvalds/linux/blob/v6.12/drivers/usb/gadget/epautoconf.c): default allocation semantics, not physical board validation.
- [RM520N Linux support commit e1091e226a2bab4ded1fe26efba2aee1aab06450](https://github.com/torvalds/linux/commit/e1091e226a2bab4ded1fe26efba2aee1aab06450): upstream device/composition example, without exact candidate firmware identity.
- [Linux v6.12 rmnet MAP code](https://github.com/torvalds/linux/blob/v6.12/drivers/net/ethernet/qualcomm/rmnet/rmnet_map_data.c) and [MAP header](https://github.com/torvalds/linux/blob/v6.12/include/linux/if_rmnet.h): source interpretation of framing/checksum fields.
- [libqmi pinned commit 1c972b8ab901565f26b9f95e1705269277bbfa1b](https://github.com/linux-mobile-broadband/libqmi/tree/1c972b8ab901565f26b9f95e1705269277bbfa1b): CTL/DMS/NAS/UIM/WDA/WDS schemas and service-name enums used in the research.
- [Pinned qmi-enums.h](https://github.com/linux-mobile-broadband/libqmi/blob/1c972b8ab901565f26b9f95e1705269277bbfa1b/src/libqmi-glib/qmi-enums.h): name annotations; unknown numeric services stay unknown.
- [USB-IF CDC 1.2 / WMC 1.1 package](https://www.usb.org/sites/default/files/CDC1.2_WMC1.1_012011_0.zip): class request/notification definitions; protocol-specific modem behavior still requires evidence.

## Controller resources

- [TI AM335x TRM](https://www.ti.com/lit/ug/spruh73q/spruh73q.pdf) and [BeagleBone Black documentation](https://docs.beagleboard.org/boards/beaglebone/black/ch05.html).
- [TI AM62x TRM](https://www.ti.com/lit/ug/spruiv7c/spruiv7c.pdf) and [SK-AM62 guide](https://www.ti.com/lit/ug/spruj40f/spruj40f.pdf).

**SOURCE_SUPPORTED:** these controller references motivate conditional platform evaluation. **UNKNOWN:** any physical board's exact endpoint/FIFO/enable result in this project.
