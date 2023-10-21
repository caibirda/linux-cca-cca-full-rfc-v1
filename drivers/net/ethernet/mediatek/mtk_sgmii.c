// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018-2019 MediaTek Inc.

/* A library for MediaTek SGMII circuit
 *
 * Author: Sean Wang <sean.wang@mediatek.com>
 *
 */

#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/phylink.h>
#include <linux/regmap.h>

#include "mtk_eth_soc.h"

static struct mtk_pcs *pcs_to_mtk_pcs(struct phylink_pcs *pcs)
{
	return container_of(pcs, struct mtk_pcs, pcs);
}

static void mtk_pcs_get_state(struct phylink_pcs *pcs,
			      struct phylink_link_state *state)
{
	struct mtk_pcs *mpcs = pcs_to_mtk_pcs(pcs);
	unsigned int bm, adv;

	/* Read the BMSR and LPA */
	regmap_read(mpcs->regmap, SGMSYS_PCS_CONTROL_1, &bm);
	regmap_read(mpcs->regmap, SGMSYS_PCS_ADVERTISE, &adv);

	phylink_mii_c22_pcs_decode_state(state, FIELD_GET(SGMII_BMSR, bm),
					 FIELD_GET(SGMII_LPA, adv));
}

static int mtk_pcs_config(struct phylink_pcs *pcs, unsigned int mode,
			  phy_interface_t interface,
			  const unsigned long *advertising,
			  bool permit_pause_to_mac)
{
	struct mtk_pcs *mpcs = pcs_to_mtk_pcs(pcs);
	unsigned int rgc3, sgm_mode, bmcr;
	int advertise, link_timer;
	bool changed, use_an;

	if (interface == PHY_INTERFACE_MODE_2500BASEX)
		rgc3 = RG_PHY_SPEED_3_125G;
	else
		rgc3 = 0;

	advertise = phylink_mii_c22_pcs_encode_advertisement(interface,
							     advertising);
	if (advertise < 0)
		return advertise;

	link_timer = phylink_get_link_timer_ns(interface);
	if (link_timer < 0)
		return link_timer;

	/* Clearing IF_MODE_BIT0 switches the PCS to BASE-X mode, and
	 * we assume that fixes it's speed at bitrate = line rate (in
	 * other words, 1000Mbps or 2500Mbps).
	 */
	if (interface == PHY_INTERFACE_MODE_SGMII) {
		sgm_mode = SGMII_IF_MODE_SGMII;
		if (phylink_autoneg_inband(mode)) {
			sgm_mode |= SGMII_REMOTE_FAULT_DIS |
				    SGMII_SPEED_DUPLEX_AN;
			use_an = true;
		} else {
			use_an = false;
		}
	} else if (phylink_autoneg_inband(mode)) {
		/* 1000base-X or 2500base-X autoneg */
		sgm_mode = SGMII_REMOTE_FAULT_DIS;
		use_an = linkmode_test_bit(ETHTOOL_LINK_MODE_Autoneg_BIT,
					   advertising);
	} else {
		/* 1000base-X or 2500base-X without autoneg */
		sgm_mode = 0;
		use_an = false;
	}

	if (use_an) {
		/* FIXME: Do we need to set AN_RESTART here? */
		bmcr = SGMII_AN_RESTART | SGMII_AN_ENABLE;
	} else {
		bmcr = 0;
	}

	/* Configure the underlying interface speed */
	regmap_update_bits(mpcs->regmap, mpcs->ana_rgc3,
			   RG_PHY_SPEED_3_125G, rgc3);

	/* Update the advertisement, noting whether it has changed */
	regmap_update_bits_check(mpcs->regmap, SGMSYS_PCS_ADVERTISE,
				 SGMII_ADVERTISE, advertise, &changed);

	/* Setup the link timer and QPHY power up inside SGMIISYS */
	regmap_write(mpcs->regmap, SGMSYS_PCS_LINK_TIMER, link_timer / 2 / 8);

	/* Update the sgmsys mode register */
	regmap_update_bits(mpcs->regmap, SGMSYS_SGMII_MODE,
			   SGMII_REMOTE_FAULT_DIS | SGMII_SPEED_DUPLEX_AN |
			   SGMII_IF_MODE_SGMII, sgm_mode);

	/* Update the BMCR */
	regmap_update_bits(mpcs->regmap, SGMSYS_PCS_CONTROL_1,
			   SGMII_AN_RESTART | SGMII_AN_ENABLE, bmcr);

	/* Release PHYA power down state */
	regmap_update_bits(mpcs->regmap, SGMSYS_QPHY_PWR_STATE_CTRL,
			   SGMII_PHYA_PWD, 0);

	return changed;
}

static void mtk_pcs_restart_an(struct phylink_pcs *pcs)
{
	struct mtk_pcs *mpcs = pcs_to_mtk_pcs(pcs);

	regmap_update_bits(mpcs->regmap, SGMSYS_PCS_CONTROL_1,
			   SGMII_AN_RESTART, SGMII_AN_RESTART);
}

static void mtk_pcs_link_up(struct phylink_pcs *pcs, unsigned int mode,
			    phy_interface_t interface, int speed, int duplex)
{
	struct mtk_pcs *mpcs = pcs_to_mtk_pcs(pcs);
	unsigned int sgm_mode;

	if (!phylink_autoneg_inband(mode)) {
		/* Force the speed and duplex setting */
		if (speed == SPEED_10)
			sgm_mode = SGMII_SPEED_10;
		else if (speed == SPEED_100)
			sgm_mode = SGMII_SPEED_100;
		else
			sgm_mode = SGMII_SPEED_1000;

		if (duplex == DUPLEX_FULL)
			sgm_mode |= SGMII_DUPLEX_FULL;

		regmap_update_bits(mpcs->regmap, SGMSYS_SGMII_MODE,
				   SGMII_DUPLEX_FULL | SGMII_SPEED_MASK,
				   sgm_mode);
	}
}

static const struct phylink_pcs_ops mtk_pcs_ops = {
	.pcs_get_state = mtk_pcs_get_state,
	.pcs_config = mtk_pcs_config,
	.pcs_an_restart = mtk_pcs_restart_an,
	.pcs_link_up = mtk_pcs_link_up,
};

int mtk_sgmii_init(struct mtk_sgmii *ss, struct device_node *r, u32 ana_rgc3)
{
	struct device_node *np;
	int i;

	for (i = 0; i < MTK_MAX_DEVS; i++) {
		np = of_parse_phandle(r, "mediatek,sgmiisys", i);
		if (!np)
			break;

		ss->pcs[i].ana_rgc3 = ana_rgc3;
		ss->pcs[i].regmap = syscon_node_to_regmap(np);
		of_node_put(np);
		if (IS_ERR(ss->pcs[i].regmap))
			return PTR_ERR(ss->pcs[i].regmap);

		ss->pcs[i].pcs.ops = &mtk_pcs_ops;
	}

	return 0;
}

struct phylink_pcs *mtk_sgmii_select_pcs(struct mtk_sgmii *ss, int id)
{
	if (!ss->pcs[id].regmap)
		return NULL;

	return &ss->pcs[id].pcs;
}
