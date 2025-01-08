/******************************************************************************
 *
 * Copyright (c) 2017 - 2019 Intel Corporation
 *
 * For licensing information, see the file 'LICENSE' in the root folder of
 * this software module.
 *
 ******************************************************************************/
/**
 * \file
 * This is the PON Adapter wrapper header file.
 */

#ifndef _PON_NET_REGISTER_H_
#define _PON_NET_REGISTER_H_

#include "pon_adapter.h"
#include "pon_adapter_errno.h"

/** \defgroup PON_NET_LIB PON Network Library Functions
 *
 *  This library covers network related functions which are related to PON
 *  applications.
 *
 *  @{
 */

/** \defgroup PON_NET_LIB_REGISTER PON Network Library Registration Functions
 *
 *  This library covers functions to register with higher layer software.
 *
 *  @{
 */

/**
 *	Register lower layer functions in higher layer module.
 *
 *	\param[in] hl_handle Pointer to higher layer module.
 *	\param[out] pa_ops Pointer to lower layer operations structure.
 *	\param[out] ll_handle Pointer to lower layer module.
 *
 *	\remarks The function returns an error code in case of error.
 *	The error code is described in \ref pon_adapter_errno.
 *
 *	\return Return value as follows:
 *	- PON_ADAPTER_SUCCESS: If successful
 *	- Other: An error code in case of error.
 */
enum pon_adapter_errno libponnet_ll_register_ops(void *hl_handle,
					const struct pa_ops **pa_ops,
					void **ll_handle);

/** @} */ /* PON_NET_LIB */

/** @} */ /* PON_NET_LIB_REGISTER */

#endif /* _PON_NET_REGISTER_H_ */
