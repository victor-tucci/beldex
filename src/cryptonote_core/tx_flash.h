// Copyright (c) 2019, The Beldex Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include "../cryptonote_basic/cryptonote_basic.h"
#include "../common/util.h"
#include "master_node_rules.h"
#include <iostream>
#include <shared_mutex>
#include <variant>

namespace master_nodes {
class master_node_list;
}

namespace cryptonote {

// FIXME TODO XXX - rename this file to flash_tx.h

class flash_tx {
public:
    enum class subquorum : uint8_t { base, future, _count };

    enum class signature_status : uint8_t { none, rejected, approved };

    /// The flash authorization height of this flash tx, i.e. the block height at the time the
    /// transaction was created.
    const uint64_t height;

    class tx_hash_visitor {
    public:
        crypto::hash operator()(const crypto::hash &h) const { return h; }
        crypto::hash operator()(const transaction &tx) const;
    };

    /// The flash transaction *or* hash.  The transaction is present when building a flash tx for
    /// flash quorum signing; for regular flash txes received via p2p this will contain the hash
    /// instead.
    std::variant<transaction, crypto::hash> tx;

    /// Returns the transaction hash
    crypto::hash get_txhash() const { return var::visit(tx_hash_visitor{}, tx); }

    class signature_verification_error : public std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    // Not default constructible
    flash_tx() = delete;

    /// Construct a new flash_tx from just a height; constructs a default transaction.
    explicit flash_tx(uint64_t height) : height{height} {
        initialize();
    }

    /// Construct a new flash_tx from a height and a hash
    explicit flash_tx(uint64_t height, const crypto::hash &txhash) : height{height}, tx{txhash} {
        initialize();
    }

    /// Obtains a unique lock on this flash tx; required for any signature-mutating method unless
    /// otherwise noted
    template <typename... Args>
    auto unique_lock(Args &&...args) { return std::unique_lock{mutex_, std::forward<Args>(args)...}; }

    /// Obtains a shared lock on this flash tx; required for any signature-dependent method unless
    /// otherwise noted
    template <typename... Args>
    auto shared_lock(Args &&...args) { return std::shared_lock{mutex_, std::forward<Args>(args)...}; }

    /**
     * Sets the maximum number of signatures for the given subquorum type, if the given size is less
     * than the ideal subquorum size.  All signatures above the given count will be set to rejected.
     * Throws a std::domain_error if the given signatures count is too large.
     *
     * This should only be called immediately after construction (thus not needing a lock) and only
     * called (at most) once per subquorum.
     *
     * You can safely omit calling this if you only care about approvals; this only affects the
     * result of `rejected()`.
     */
    void limit_signatures(subquorum q, size_t max_size);

    /**
     * Adds a signature for the given quorum and position given an already-obtained flash subquorum
     * validator pubkey.  Returns true if the signature was accepted and stored, false if a
     * signature was already present for the given quorum and position.  Throws a
     * `flash_tx::signature_verification_error` if the signature fails validation.
     */
    bool add_signature(subquorum q, int position, bool approved, const crypto::signature &sig, const crypto::public_key &pubkey);

    /**
     * Adds a signature for the given quorum and position.  Returns false if a signature was already
     * present; true if the signature was accepted and stored; and throws a
     * `flash_tx::signature_verification_error` if the signature fails validation.
     */
    bool add_signature(subquorum q, int position, bool approved, const crypto::signature &sig, const master_nodes::master_node_list &snl);

    /**
     * Adds a signature for the given quorum and position without checking it for validity (i.e.
     * because it has already been checked with crypto::check_signature).  Returns true if added,
     * false if a signature was already present.
     */
    bool add_prechecked_signature(subquorum q, int position, bool approved, const crypto::signature &sig);

    /**
     * Returns the signature status for the given subquorum and position.
     */
    signature_status get_signature_status(subquorum q, int position) const;

    /**
     * Returns true if this flash tx is valid for inclusion in the blockchain, that is, has the
     * required number of approval signatures in each quorum.  (Note that it is possible for a flash
     * tx to be neither approved() nor rejected()).
     */
    bool approved() const;

    /**
     * Returns true if this flash tx has been definitively rejected, that is, has enough rejection
     * signatures in at least one of the quorums that it is impossible for it to become approved().
     * (Note that it is possible for a flash tx to be neither approved() nor rejected()).
     */
    bool rejected() const;

    /// Returns the quorum height for the given height and quorum (base or future); returns 0 at the
    /// beginning of the chain (before there are enough blocks for a flash quorum).
    static uint64_t quorum_height(uint64_t h, subquorum q) {
        uint64_t bh = h - (h % master_nodes::FLASH_QUORUM_INTERVAL) - master_nodes::FLASH_QUORUM_LAG
            + static_cast<uint8_t>(q) * master_nodes::FLASH_QUORUM_INTERVAL;
        return bh > h /*overflow*/ ? 0 : bh;
    }

    /// Returns the height of the given subquorum (base or future) for this flash tx; returns 0 at
    /// the beginning of the chain (before there are enough blocks for a flash quorum).  Lock not
    /// required.
    uint64_t quorum_height(subquorum q) const { return quorum_height(height, q); }

    /// Returns the pubkey of the referenced master node, or null if there is no such master node.
    crypto::public_key get_mn_pubkey(subquorum q, int position, const master_nodes::master_node_list &snl) const;

    /// Returns the hashed signing value for this flash TX for a tx with status `approved`.  The
    /// result is a fast hash of the height + tx hash + approval value.  Lock not required.
    crypto::hash hash(bool approved) const;

    struct quorum_signature {
        signature_status status;
        crypto::signature sig;
    };

    /**
     * Fills the given flash serialization struct with the signature data.  This is designed to work
     * directly with the components of a serializable_flash_metadata (but we don't want to have to
     * link to cryptonote_protocol where that is defined).
     *
     * A shared lock should be held by the caller.
     */
    void fill_serialization_data(crypto::hash &tx_hash, uint64_t &height, std::vector<uint8_t> &quorum, std::vector<uint8_t> &position, std::vector<crypto::signature> &signature) const;

    /// Wrapper around the above that can be called with a serializable_flash_metadata
    template <typename T>
    void fill_serialization_data(T &data) const { fill_serialization_data(data.tx_hash, data.height, data.quorum, data.position, data.signature); }

private:
    void initialize() {
        assert(quorum_height(subquorum::base) > 0);
        for (auto &q : signatures_)
            for (auto &s : q)
                s.status = signature_status::none;
    }

    std::array<std::array<quorum_signature, master_nodes::FLASH_SUBQUORUM_SIZE>, tools::enum_count<subquorum>> signatures_;
    std::shared_mutex mutex_;
};

}
