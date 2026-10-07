/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.eudi.wallet.transfer.openId4vp.dcql

import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import org.multipaz.presentment.CredentialMatchSourceOpenID4VP
import org.multipaz.presentment.CredentialQueryResult
import org.multipaz.presentment.CredentialSelection
import org.multipaz.presentment.CredentialPresentmentSet
import org.multipaz.presentment.CredentialPresentmentSetOption
import org.multipaz.presentment.CredentialPresentmentSetOptionMember
import org.multipaz.presentment.CredentialPresentmentSetOptionMemberMatch

/**
 * Builds the list of options the user can choose from, applying each query's
 * `multiple` flag:
 *  - `multiple = false` (default): each candidate credential becomes its own option.
 *  - `multiple = true`: all candidates of the query are grouped into one option.
 *
 * Each member is matched back to its query through the match source; missing sources
 * are treated as `multiple = false`. Optional sets add an extra "skip" option so the
 * user can leave them out. The final list combines all per-member options across
 * credential sets and their members.
 *
 * @param data the input presentment tree.
 * @param multipleByQueryId the `multiple` flag per query (missing keys default to `false`).
 * @return the list of options, or an empty list when nothing can satisfy the request.
 */
internal fun buildMultipleAwareSelections(
    data: CredentialQueryResult,
    multipleByQueryId: Map<QueryId, Boolean>,
): List<CredentialSelection> {

    // Each member's matches become one or more picks, depending on the query's flag.
    fun picksForMember(
        member: CredentialPresentmentSetOptionMember,
    ): List<List<CredentialPresentmentSetOptionMemberMatch>> {
        return if (member.allowsMultiple(multipleByQueryId)) {
            // One pick that carries every match together.
            listOf(member.matches)
        } else {
            // One pick per match.
            member.matches.map { listOf(it) }
        }
    }

    // For each option, combine its members' picks into one flat list per combination.
    fun picksForOption(
        option: CredentialPresentmentSetOption,
    ): List<List<CredentialPresentmentSetOptionMemberMatch>> {
        val perMember = option.members.map { picksForMember(it) }
        return cartesianProduct(perMember).map { perMemberPicks -> perMemberPicks.flatten() }
    }

    // For each set, gather picks from every option, plus an empty "skip" pick when
    // the set is optional.
    fun picksForSet(
        set: CredentialPresentmentSet,
    ): List<List<CredentialPresentmentSetOptionMemberMatch>> = buildList {
        if (set.optional) add(emptyList())
        set.options.forEach { addAll(picksForOption(it)) }
    }

    // Combine the per-set picks into the final list of options.
    val perSet = data.credentialSets.map { picksForSet(it) }
    return cartesianProduct(perSet).map { perSetPicks ->
        CredentialSelection(matches = perSetPicks.flatten())
    }
}

/**
 * The most options [buildMultipleAwareSelections] may produce for a request. Every option is built
 * in memory, and their number is the product of the choices of every credential set, so it grows
 * exponentially with the credential sets. This many options are more than a consent screen can
 * usefully present.
 */
internal const val MAX_PRESENTMENT_SELECTIONS = 1000L

/**
 * Counts the options [buildMultipleAwareSelections] produces for the same input, without
 * building them. The count stops growing at [cap], so it is exact below [cap] and [cap] otherwise.
 *
 * @param data the input presentment tree.
 * @param multipleByQueryId the `multiple` flag per query (missing keys default to `false`).
 * @param cap the value at which the count stops growing.
 * @return the number of options, or [cap] when there are at least that many.
 */
internal fun countMultipleAwareSelections(
    data: CredentialQueryResult,
    multipleByQueryId: Map<QueryId, Boolean>,
    cap: Long = MAX_PRESENTMENT_SELECTIONS + 1,
): Long {
    fun Long.timesCapped(other: Long): Long = when {
        this == 0L || other == 0L -> 0L
        this > cap / other -> cap
        else -> this * other
    }

    fun Long.plusCapped(other: Long): Long = minOf(this + other, cap)

    return data.credentialSets.fold(1L) { total, set ->
        val setCount = set.options.fold(if (set.optional) 1L else 0L) { sum, option ->
            val optionCount = option.members.fold(1L) { product, member ->
                val picks = if (member.allowsMultiple(multipleByQueryId)) 1L else member.matches.size.toLong()
                product.timesCapped(picks)
            }
            sum.plusCapped(optionCount)
        }
        total.timesCapped(setCount)
    }
}

/**
 * Whether the query of the member's matches has `multiple = true`. A member whose matches have no
 * query is treated as `multiple = false`.
 */
private fun CredentialPresentmentSetOptionMember.allowsMultiple(
    multipleByQueryId: Map<QueryId, Boolean>,
): Boolean {
    val queryId = matches.firstOrNull()
        ?.let { (it.source as? CredentialMatchSourceOpenID4VP)?.credentialQuery?.id }
        ?.let(::QueryId)
    return queryId?.let { multipleByQueryId[it] } ?: false
}

/**
 * Combines lists of options into every possible combination:
 * `[[a, b], [c, d, e]] → [[a, c], [a, d], [a, e], [b, c], [b, d], [b, e]]`.
 *
 * Used internally by [buildMultipleAwareSelections]. An empty input gives back a single
 * empty combination (`[[]]`).
 */
private fun <T> cartesianProduct(lists: List<List<T>>): List<List<T>> {
    if (lists.isEmpty()) return listOf(emptyList())
    return lists.fold(listOf(emptyList())) { acc, list ->
        acc.flatMap { prefix -> list.map { item -> prefix + item } }
    }
}