// Taskweft HTN planner — pure C++20, no Godot dependency.
// Depth-first search over method decompositions, porting IPyHOP's seek_plan().
#pragma once
#include "tw_domain.hpp"
#include "tw_soltree.hpp"
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

static constexpr int TW_MAX_DEPTH = 256;

// Default planner wall-clock budget — the industry-standard knob for
// bounding HTN search instead of relying solely on a static depth limit.
// Adversarial or pathological domains hit the wall clock long before any
// sensible depth, so this is the real DoS guard.
static constexpr std::chrono::milliseconds TW_DEFAULT_BUDGET{5000};

// Granularity at which `tw_seek_plan` consults the wall clock. One probe
// per recursion entry would work but `steady_clock::now()` costs ~10ns
// on Apple silicon and the planner is microsecond-scale on legitimate
// inputs; sampling every 256 entries keeps the overhead invisible while
// still bounding adversarial loops to ~µs of overshoot.
static constexpr int TW_BUDGET_SAMPLE_EVERY = 256;

struct TwBudget {
    std::chrono::steady_clock::time_point deadline;
    int                                   tick   = 0;
    bool                                  fired  = false;

    static TwBudget from_now(std::chrono::milliseconds ms) {
        return TwBudget{std::chrono::steady_clock::now() + ms, 0, false};
    }

    bool exceeded() {
        if (fired) return true;
        if ((++tick % TW_BUDGET_SAMPLE_EVERY) != 0) return false;
        if (std::chrono::steady_clock::now() >= deadline) {
            fired = true;
            return true;
        }
        return false;
    }
};

// Thrown out of `tw_seek_plan` when the wall-clock budget is exhausted.
// NIF callers translate to a distinct error so consumers can tell
// "no plan exists" from "we ran out of time".
struct TwBudgetExceeded : std::runtime_error {
    TwBudgetExceeded() : std::runtime_error("planner_time_budget_exceeded") {}
};

// Serialize a TwCall to a canonical string key for blacklist membership tests.
// Mirrors Python's tuple identity: ("action_name", arg1, arg2, ...).
inline std::string tw_call_key(const TwCall &call) {
    std::string key = call.name;
    for (const TwValue &a : call.args) { key += '\x1f'; key += a.to_string(); }
    return key;
}

// A set of blacklisted command keys (serialized TwCalls).
// Blacklisted commands are skipped during planning — used by replan to avoid
// repeating the same (action, concrete_args) that failed at runtime.
// Mirrors IPyHOP planner.blacklist / blacklist_command().
using TwBlacklist = std::unordered_set<std::string>;

inline std::optional<std::vector<TwCall>> tw_seek_plan(
        std::shared_ptr<TwState> state,
        std::vector<TwTask>      tasks,
        const TwDomain           &domain,
        int                      depth = 0,
        const TwBlacklist       *blacklist = nullptr,
        TwBudget                *budget = nullptr) {

    if (budget && budget->exceeded()) throw TwBudgetExceeded{};
    if (depth > TW_MAX_DEPTH) return std::nullopt;
    if (tasks.empty()) return std::vector<TwCall>{};

    std::vector<TwTask> remaining(tasks.begin() + 1, tasks.end());

    // --- Conjunctive goal (unigoal) ---
    if (TwGoal *goal = std::get_if<TwGoal>(&tasks[0])) {
        if (goal->is_satisfied(*state))
            return tw_seek_plan(state, remaining, domain, depth + 1, blacklist, budget);

        std::vector<TwGoalBinding> unmet = goal->unsatisfied(*state);
        if (unmet.empty()) return std::nullopt;

        // Pick first unsatisfied binding; try all goal methods for its var.
        const TwGoalBinding &b = unmet[0];
        std::unordered_map<std::string, std::vector<TwGoalMethodFn>>::const_iterator git =
            domain.goal_methods.find(b.var);
        if (git == domain.goal_methods.end()) return std::nullopt;

        std::vector<TwValue> goal_args = {TwValue(b.key), b.desired};
        for (const TwGoalMethodFn &method : git->second) {
            std::optional<std::vector<TwTask>> subs = method(state, goal_args);
            if (!subs) continue;
            std::vector<TwTask> new_tasks;
            new_tasks.insert(new_tasks.end(), subs->begin(), subs->end());
            new_tasks.push_back(*goal);
            new_tasks.insert(new_tasks.end(), remaining.begin(), remaining.end());
            std::optional<std::vector<TwCall>> result =
                tw_seek_plan(state, new_tasks, domain, depth + 1, blacklist, budget);
            if (result) return result;
        }
        return std::nullopt;
    }

    // --- Multigoal (RECTGTN 'N'): backtrack over which binding to satisfy first ---
    if (TwMultiGoal *mg = std::get_if<TwMultiGoal>(&tasks[0])) {
        if (mg->is_satisfied(*state))
            return tw_seek_plan(state, remaining, domain, depth + 1, blacklist, budget);

        std::vector<TwGoalBinding> unmet = mg->unsatisfied(*state);
        if (unmet.empty()) return std::nullopt;

        // Try each unsatisfied binding as the next thing to satisfy (IPyHOP _mg).
        for (size_t idx = 0; idx < unmet.size(); ++idx) {
            TwGoal sub_goal;
            sub_goal.bindings = {unmet[idx]};

            std::vector<TwTask> new_tasks;
            new_tasks.push_back(sub_goal);
            new_tasks.push_back(*mg);
            new_tasks.insert(new_tasks.end(), remaining.begin(), remaining.end());
            std::optional<std::vector<TwCall>> result =
                tw_seek_plan(state, new_tasks, domain, depth + 1, blacklist, budget);
            if (result) return result;
        }
        return std::nullopt;
    }

    // --- Primitive action or compound task ---
    TwCall &call = std::get<TwCall>(tasks[0]);

    // Primitive action (RECTGTN 'E' — a command that can fail at runtime).
    std::unordered_map<std::string, TwActionFn>::const_iterator ait =
        domain.actions.find(call.name);
    if (ait != domain.actions.end()) {
        // Skip blacklisted commands — specific (action, args) instances that
        // failed at runtime and must not be replanned (IPyHOP blacklist_command).
        if (blacklist && blacklist->count(tw_call_key(call))) return std::nullopt;

        std::shared_ptr<TwState> new_state = ait->second(state->copy(), call.args);
        if (!new_state) return std::nullopt;
        std::optional<std::vector<TwCall>> sub =
            tw_seek_plan(new_state, remaining, domain, depth + 1, blacklist, budget);
        if (!sub) return std::nullopt;
        std::vector<TwCall> plan = {call};
        plan.insert(plan.end(), sub->begin(), sub->end());
        return plan;
    }

    // Compound task: try each method in order
    std::unordered_map<std::string, std::vector<TwMethodFn>>::const_iterator mit =
        domain.task_methods.find(call.name);
    if (mit != domain.task_methods.end()) {
        for (const TwMethodFn &method : mit->second) {
            std::optional<std::vector<TwTask>> subs = method(state, call.args);
            if (!subs) continue;
            std::vector<TwTask> new_tasks;
            new_tasks.insert(new_tasks.end(), subs->begin(), subs->end());
            new_tasks.insert(new_tasks.end(), remaining.begin(), remaining.end());
            std::optional<std::vector<TwCall>> result =
                tw_seek_plan(state, new_tasks, domain, depth + 1, blacklist, budget);
            if (result) return result;
        }
        return std::nullopt;
    }

    return std::nullopt;
}

inline std::optional<std::vector<TwCall>> tw_plan(
        std::shared_ptr<TwState>   state,
        std::vector<TwTask>        tasks,
        const TwDomain            &domain,
        const TwBlacklist         *blacklist = nullptr,
        std::chrono::milliseconds  budget_ms = TW_DEFAULT_BUDGET) {
    TwBudget budget = TwBudget::from_now(budget_ms);
    return tw_seek_plan(std::move(state), std::move(tasks), domain, 0, blacklist, &budget);
}

// ── Tree-building planner ───────────────────────────────────────────────────
// Like tw_seek_plan, but simultaneously builds a TwSolTree recording the
// method chosen at each decomposition.  On a failed subtree the tree is
// rolled back to its checkpoint before trying the next alternative.
// method_skip: optional per-task set of method indices to skip (used by
// incremental replan to avoid repeating the method that produced the failed plan).
inline std::optional<std::vector<TwCall>> tw_seek_plan_tree(
        std::shared_ptr<TwState>  state,
        std::vector<TwTask>       tasks,
        const TwDomain            &domain,
        TwSolTree                 *tree,
        int                        tree_parent,
        int                        depth      = 0,
        const TwBlacklist         *blacklist   = nullptr,
        const TwMethodSkip        *method_skip = nullptr,
        TwBudget                  *budget      = nullptr) {

    if (budget && budget->exceeded()) throw TwBudgetExceeded{};
    if (depth > TW_MAX_DEPTH) return std::nullopt;
    if (tasks.empty()) return std::vector<TwCall>{};

    std::vector<TwTask> remaining(tasks.begin() + 1, tasks.end());

    // --- Conjunctive goal (unigoal) ---
    if (TwGoal *goal = std::get_if<TwGoal>(&tasks[0])) {
        if (goal->is_satisfied(*state))
            return tw_seek_plan_tree(state, remaining, domain, tree, tree_parent,
                                     depth + 1, blacklist, method_skip, budget);

        std::vector<TwGoalBinding> unmet = goal->unsatisfied(*state);
        if (unmet.empty()) return std::nullopt;

        const TwGoalBinding &b = unmet[0];
        std::unordered_map<std::string, std::vector<TwGoalMethodFn>>::const_iterator git =
            domain.goal_methods.find(b.var);
        if (git == domain.goal_methods.end()) return std::nullopt;

        std::vector<TwValue> goal_args = {TwValue(b.key), b.desired};
        std::string gkey; // for method_skip lookup
        if (method_skip) {
            TwCall gc; gc.name = b.var; gc.args = goal_args;
            gkey = tw_call_key(gc);
        }
        for (size_t m = 0; m < git->second.size(); ++m) {
            if (method_skip) {
                std::unordered_map<std::string, std::unordered_set<int>>::const_iterator si =
                    method_skip->find(gkey);
                if (si != method_skip->end() && si->second.count((int)m)) continue;
            }
            std::optional<std::vector<TwTask>> subs = git->second[m](state, goal_args);
            if (!subs) continue;

            int cp      = tree ? tree->checkpoint() : 0;
            int first   = tree ? (int)tree->action_nodes.size() : 0;
            int gnode   = tree ? tree->add_node(TwSolNode::Kind::Goal, tree_parent,
                                                b.var, goal_args, (int)m) : -1;
            if (tree) tree->nodes[gnode].first_step = first;
            int next_p  = tree ? gnode : tree_parent;

            std::vector<TwTask> new_tasks;
            new_tasks.insert(new_tasks.end(), subs->begin(), subs->end());
            new_tasks.push_back(*goal);
            new_tasks.insert(new_tasks.end(), remaining.begin(), remaining.end());
            std::optional<std::vector<TwCall>> result =
                tw_seek_plan_tree(state, new_tasks, domain, tree, next_p,
                                  depth + 1, blacklist, method_skip, budget);
            if (result) return result;
            if (tree) tree->restore(cp);
        }
        return std::nullopt;
    }

    // --- Multigoal (RECTGTN 'N') ---
    if (TwMultiGoal *mg = std::get_if<TwMultiGoal>(&tasks[0])) {
        if (mg->is_satisfied(*state))
            return tw_seek_plan_tree(state, remaining, domain, tree, tree_parent,
                                     depth + 1, blacklist, method_skip, budget);

        std::vector<TwGoalBinding> unmet = mg->unsatisfied(*state);
        if (unmet.empty()) return std::nullopt;

        for (size_t idx = 0; idx < unmet.size(); ++idx) {
            TwGoal sub_goal;
            sub_goal.bindings = {unmet[idx]};
            std::vector<TwTask> new_tasks;
            new_tasks.push_back(sub_goal);
            new_tasks.push_back(*mg);
            new_tasks.insert(new_tasks.end(), remaining.begin(), remaining.end());
            std::optional<std::vector<TwCall>> result =
                tw_seek_plan_tree(state, new_tasks, domain, tree, tree_parent,
                                  depth + 1, blacklist, method_skip, budget);
            if (result) return result;
        }
        return std::nullopt;
    }

    // --- Primitive action or compound task ---
    TwCall &call = std::get<TwCall>(tasks[0]);

    // Primitive action (RECTGTN 'E')
    std::unordered_map<std::string, TwActionFn>::const_iterator ait =
        domain.actions.find(call.name);
    if (ait != domain.actions.end()) {
        if (blacklist && blacklist->count(tw_call_key(call))) return std::nullopt;

        std::shared_ptr<TwState> new_state = ait->second(state->copy(), call.args);
        if (!new_state) return std::nullopt;

        int cp    = tree ? tree->checkpoint() : 0;
        int step  = tree ? (int)tree->action_nodes.size() : 0;
        int anode = -1;
        if (tree) {
            anode = tree->add_node(TwSolNode::Kind::Action, tree_parent, call.name, call.args);
            tree->nodes[anode].plan_step = step;
            tree->action_nodes.push_back(anode);
        }

        std::optional<std::vector<TwCall>> sub =
            tw_seek_plan_tree(new_state, remaining, domain, tree, tree_parent,
                              depth + 1, blacklist, method_skip, budget);
        if (!sub) {
            if (tree) tree->restore(cp);
            return std::nullopt;
        }
        std::vector<TwCall> plan = {call};
        plan.insert(plan.end(), sub->begin(), sub->end());
        return plan;
    }

    // Compound task (RECTGTN 'T')
    std::unordered_map<std::string, std::vector<TwMethodFn>>::const_iterator mit =
        domain.task_methods.find(call.name);
    if (mit != domain.task_methods.end()) {
        std::string tkey = method_skip ? tw_call_key(call) : std::string{};
        for (size_t m = 0; m < mit->second.size(); ++m) {
            if (method_skip) {
                std::unordered_map<std::string, std::unordered_set<int>>::const_iterator si =
                    method_skip->find(tkey);
                if (si != method_skip->end() && si->second.count((int)m)) continue;
            }
            std::optional<std::vector<TwTask>> subs = mit->second[m](state, call.args);
            if (!subs) continue;

            int cp    = tree ? tree->checkpoint() : 0;
            int first = tree ? (int)tree->action_nodes.size() : 0;
            int tnode = tree ? tree->add_node(TwSolNode::Kind::Task, tree_parent,
                                              call.name, call.args, (int)m) : -1;
            if (tree) tree->nodes[tnode].first_step = first;
            int next_p = tree ? tnode : tree_parent;

            std::vector<TwTask> new_tasks;
            new_tasks.insert(new_tasks.end(), subs->begin(), subs->end());
            new_tasks.insert(new_tasks.end(), remaining.begin(), remaining.end());
            std::optional<std::vector<TwCall>> result =
                tw_seek_plan_tree(state, new_tasks, domain, tree, next_p,
                                  depth + 1, blacklist, method_skip, budget);
            if (result) return result;
            if (tree) tree->restore(cp);
        }
        return std::nullopt;
    }

    return std::nullopt;
}

// Plan and simultaneously build a solution derivation tree.
// The tree can be passed to tw_replan_incremental to backtrack at the exact
// method choice point rather than restarting the full search.
inline std::optional<std::vector<TwCall>> tw_plan_with_tree(
        std::shared_ptr<TwState>   state,
        std::vector<TwTask>        tasks,
        const TwDomain            &domain,
        TwSolTree                 &out_tree,
        const TwBlacklist         *blacklist   = nullptr,
        const TwMethodSkip        *method_skip = nullptr,
        std::chrono::milliseconds  budget_ms   = TW_DEFAULT_BUDGET) {
    out_tree.nodes.clear();
    out_tree.action_nodes.clear();
    TwSolNode root;
    root.kind   = TwSolNode::Kind::Root;
    root.parent = -1;
    out_tree.nodes.push_back(root);
    TwBudget budget = TwBudget::from_now(budget_ms);
    return tw_seek_plan_tree(std::move(state), std::move(tasks), domain,
                             &out_tree, 0, 0, blacklist, method_skip, &budget);
}
