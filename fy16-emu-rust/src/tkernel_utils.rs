use strum_macros::Display;
use crate::num_derive::FromPrimitive;

#[derive(FromPrimitive, Display)]
pub enum TkFunIds {
    None = 0x00000000,
    TFN_CRE_TSK = 0x80010100,
    TFN_DEL_TSK = 0x80020100,
    TFN_STA_TSK = 0x80030200,
    TFN_EXT_TSK = 0x80040000,
    TFN_EXD_TSK = 0x80050000,
    TFN_TER_TSK = 0x80060100,
    TFN_DIS_DSP = 0x80070000,
    TFN_ENA_DSP = 0x80080000,
    TFN_CHG_PRI = 0x80090200,
    TFN_CHG_SLT = 0x800a0200,
    TFN_ROT_RDQ = 0x800b0100,
    TFN_REL_WAI = 0x800c0100,
    TFN_GET_TID = 0x800d0000,
    TFN_GET_TSP = 0x800e0200,
    TFN_SET_TSP = 0x800f0200,
    TFN_GET_RID = 0x80100100,
    TFN_SET_RID = 0x80110200,
    TFN_GET_REG = 0x80120400,
    TFN_SET_REG = 0x80130400,
    TFN_GET_CPR = 0x80140300,
    TFN_SET_CPR = 0x80150300,
    TFN_INF_TSK = 0x80160300,
    TFN_REF_TSK = 0x80170200,
    TFN_DEF_TEX = 0x80180200,
    TFN_ENA_TEX = 0x80190200,
    TFN_DIS_TEX = 0x801a0200,
    TFN_RAS_TEX = 0x801b0200,
    TFN_END_TEX = 0x801c0100,
    TFN_REF_TEX = 0x801d0200,
    TFN_SUS_TSK = 0x801e0100,
    TFN_RSM_TSK = 0x801f0100,
    TFN_FRSM_TSK = 0x80200100,
    TFN_SLP_TSK = 0x80210100,
    TFN_WUP_TSK = 0x80220100,
    TFN_CAN_WUP = 0x80230100,
    TFN_SIG_TEV = 0x80240200,
    TFN_WAI_TEV = 0x80250200,
    TFN_DIS_WAI = 0x80260200,
    TFN_ENA_WAI = 0x80270100,
    TFN_CRE_SEM = 0x80280100,
    TFN_DEL_SEM = 0x80290100,
    TFN_SIG_SEM = 0x802a0200,
    TFN_WAI_SEM = 0x802b0300,
    TFN_REF_SEM = 0x802c0200,
    TFN_CRE_MTX = 0x802d0100,
    TFN_DEL_MTX = 0x802e0100,
    TFN_LOC_MTX = 0x802f0200,
    TFN_UNL_MTX = 0x80300100,
    TFN_REF_MTX = 0x80310200,
    TFN_CRE_FLG = 0x80320100,
    TFN_DEL_FLG = 0x80330100,
    TFN_SET_FLG = 0x80340200,
    TFN_CLR_FLG = 0x80350200,
    TFN_WAI_FLG = 0x80360500,
    TFN_REF_FLG = 0x80370200,
    TFN_CRE_MBX = 0x80380100,
    TFN_DEL_MBX = 0x80390100,
    TFN_SND_MBX = 0x803a0200,
    TFN_RCV_MBX = 0x803b0300,
    TFN_REF_MBX = 0x803c0200,
    TFN_CRE_MBF = 0x803d0100,
    TFN_DEL_MBF = 0x803e0100,
    TFN_SND_MBF = 0x803f0400,
    TFN_RCV_MBF = 0x80400300,
    TFN_REF_MBF = 0x80410200,
    TFN_CRE_POR = 0x80420100,
    TFN_DEL_POR = 0x80430100,
    TFN_CAL_POR = 0x80440500,
    TFN_ACP_POR = 0x80450500,
    TFN_FWD_POR = 0x80460500,
    TFN_RPL_RDV = 0x80470300,
    TFN_REF_POR = 0x80480200,
    TFN_DEF_INT = 0x80490200,
    TFN_RET_INT = 0x804a0000,
    TFN_CRE_MPL = 0x804b0100,
    TFN_DEL_MPL = 0x804c0100,
    TFN_GET_MPL = 0x804d0400,
    TFN_REL_MPL = 0x804e0200,
    TFN_REF_MPL = 0x804f0200,
    TFN_CRE_MPF = 0x80500100,
    TFN_DEL_MPF = 0x80510100,
    TFN_GET_MPF = 0x80520300,
    TFN_REL_MPF = 0x80530200,
    TFN_REF_MPF = 0x80540200,
    TFN_SET_TIM = 0x80550100,
    TFN_GET_TIM = 0x80560100,
    TFN_GET_OTM = 0x80570100,
    TFN_DLY_TSK = 0x80580100,
    TFN_CRE_CYC = 0x80590100,
    TFN_DEL_CYC = 0x805a0100,
    TFN_STA_CYC = 0x805b0100,
    TFN_STP_CYC = 0x805c0100,
    TFN_REF_CYC = 0x805d0200,
    TFN_CRE_ALM = 0x805e0100,
    TFN_DEL_ALM = 0x805f0100,
    TFN_STA_ALM = 0x80600200,
    TFN_STP_ALM = 0x80610100,
    TFN_REF_ALM = 0x80620200,
    TFN_REF_VER = 0x80630100,
    TFN_REF_SYS = 0x80640100,
    TFN_DEF_SSY = 0x80650200,
    TFN_STA_SSY = 0x80660300,
    TFN_CLN_SSY = 0x80670300,
    TFN_EVT_SSY = 0x80680400,
    TFN_REF_SSY = 0x80690200,
    TFN_CRE_RES = 0x806a0000,
    TFN_DEL_RES = 0x806b0100,
    TFN_GET_RES = 0x806c0300,
    TFN_SET_POW = 0x806d0100,
    TFN_CHG_SLT_U = 0x806e0300,
    TFN_INF_TSK_U = 0x806f0300,
    TFN_REF_TSK_U = 0x80700200,
    TFN_SLP_TSK_U = 0x80710200,
    TFN_WAI_TEV_U = 0x80720300,
    TFN_DLY_TSK_U = 0x80730200,
    TFN_WAI_SEM_U = 0x80740400,
    TFN_WAI_FLG_U = 0x80750600,
    TFN_RCV_MBX_U = 0x80760400,
    TFN_LOC_MTX_U = 0x80770300,
    TFN_SND_MBF_U = 0x80780500,
    TFN_RCV_MBF_U = 0x80790400,
    TFN_CAL_POR_U = 0x807a0600,
    TFN_ACP_POR_U = 0x807b0600,
    TFN_GET_MPL_U = 0x807c0500,
    TFN_GET_MPF_U = 0x807d0400,
    TFN_SET_TIM_U = 0x807e0200,
    TFN_GET_TIM_U = 0x807f0200,
    TFN_GET_OTM_U = 0x80800200,
    TFN_CRE_CYC_U = 0x80810100,
    TFN_REF_CYC_U = 0x80820200,
    TFN_STA_ALM_U = 0x80830300,
    TFN_REF_ALM_U = 0x80840200,
}

#[derive(FromPrimitive, Display)]

pub enum AltTkFunIds {
    None = 0x00000000,
    TFN_tk_get_cfn = 0x80010300,
    TFN_tk_get_cfs = 0x80020300
}

