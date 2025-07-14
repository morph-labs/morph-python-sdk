"""
Garbage Collection module for MorphCloud snapshots.

This module implements the core garbage collection logic for snapshot cleanup:
- Tree traversal and reachability analysis
- GC root identification
- Cycle detection
- Snapshot classification (reachable/unreachable)
"""

import logging
from typing import List, Set, Dict, Optional, Tuple
from dataclasses import dataclass

from morphcloud.api import Snapshot, Instance, InstanceStatus

logger = logging.getLogger(__name__)


@dataclass
class SnapshotClassification:
    """Classification of snapshots for garbage collection."""
    gc_roots: Set[str]          # Never delete - active instances, tagged snapshots
    reachable: Set[str]         # Never delete - ancestors of GC roots
    unreachable: Set[str]       # Safe to delete - no path to any GC root
    broken_chains: Set[str]     # Orphaned snapshots with invalid parent pointers
    cycles_detected: List[List[str]]  # Detected cycles in parent chains


class SnapshotGarbageCollector:
    """Core garbage collection engine for snapshots."""
    
    def __init__(self, max_traversal_depth: int = 1000):
        """
        Initialize the garbage collector.
        
        Args:
            max_traversal_depth: Maximum depth to traverse parent chains (cycle protection)
        """
        self.max_traversal_depth = max_traversal_depth
        self.snapshot_lookup: Dict[str, Snapshot] = {}
        
    def classify_snapshots(self, snapshots: List[Snapshot], instances: List[Instance]) -> SnapshotClassification:
        """
        Classify all snapshots into GC categories.
        
        Args:
            snapshots: List of all snapshots to analyze
            instances: List of all instances (for finding active references)
            
        Returns:
            SnapshotClassification with categorized snapshot IDs
        """
        # Build lookup table for efficient snapshot access
        self.snapshot_lookup = {s.id: s for s in snapshots}
        
        classification = SnapshotClassification(
            gc_roots=set(),
            reachable=set(),
            unreachable=set(),
            broken_chains=set(),
            cycles_detected=[]
        )
        
        # Step 1: Find GC roots
        classification.gc_roots = self._find_gc_roots(snapshots, instances)
        logger.info(f"Found {len(classification.gc_roots)} GC roots")
        
        # Step 2: Mark reachable snapshots by traversing parent chains
        for root_id in classification.gc_roots:
            try:
                self._mark_reachable_chain(root_id, classification)
            except Exception as e:
                logger.error(f"Error traversing chain from root {root_id}: {e}")
                continue
        
        # Step 3: Identify unreachable snapshots
        for snapshot in snapshots:
            if snapshot.id not in classification.reachable:
                classification.unreachable.add(snapshot.id)
        
        logger.info(f"Classification complete: {len(classification.reachable)} reachable, "
                   f"{len(classification.unreachable)} unreachable, "
                   f"{len(classification.broken_chains)} broken chains, "
                   f"{len(classification.cycles_detected)} cycles detected")
        
        return classification
    
    def _find_gc_roots(self, snapshots: List[Snapshot], instances: List[Instance]) -> Set[str]:
        """
        Find all GC roots (snapshots that should never be deleted).
        
        GC roots include:
        1. Snapshots used by active instances (READY, PAUSED, PENDING)
        2. Tagged snapshots (metadata["tag"] exists)
        3. Explicitly protected snapshots (metadata["gc_keep"] = "true")
        
        Returns:
            Set of snapshot IDs that are GC roots
        """
        gc_roots = set()
        
        # 1. Active instance snapshots
        active_statuses = {InstanceStatus.READY, InstanceStatus.PAUSED, InstanceStatus.PENDING}
        for instance in instances:
            if instance.status in active_statuses:
                gc_roots.add(instance.refs.snapshot_id)
                logger.debug(f"GC root: {instance.refs.snapshot_id} (active instance {instance.id})")
        
        # 2. Tagged snapshots and explicitly protected snapshots
        for snapshot in snapshots:
            if not snapshot.metadata:
                continue
                
            # Tagged snapshots
            if snapshot.metadata.get("tag"):
                gc_roots.add(snapshot.id)
                logger.debug(f"GC root: {snapshot.id} (tagged: {snapshot.metadata['tag']})")
            
            # Explicitly protected snapshots
            if snapshot.metadata.get("gc_keep") == "true":
                gc_roots.add(snapshot.id)
                logger.debug(f"GC root: {snapshot.id} (explicitly protected)")
        
        return gc_roots
    
    def _mark_reachable_chain(self, snapshot_id: str, classification: SnapshotClassification):
        """
        Mark all snapshots in the parent chain as reachable.
        
        Walks up the parent chain from the given snapshot, marking each ancestor
        as reachable. Includes cycle detection and broken chain handling.
        
        Args:
            snapshot_id: Starting snapshot ID (usually a GC root)
            classification: Classification object to update
        """
        visited_in_chain = []  # Track current traversal path for cycle detection
        current_id = snapshot_id
        
        while current_id and len(visited_in_chain) < self.max_traversal_depth:
            # Cycle detection
            if current_id in visited_in_chain:
                cycle_start = visited_in_chain.index(current_id)
                cycle = visited_in_chain[cycle_start:] + [current_id]
                classification.cycles_detected.append(cycle)
                logger.warning(f"Cycle detected: {' → '.join(cycle)}")
                break
            
            # Already processed in another chain - optimization
            if current_id in classification.reachable:
                break
            
            visited_in_chain.append(current_id)
            classification.reachable.add(current_id)
            
            # Find parent snapshot
            snapshot = self.snapshot_lookup.get(current_id)
            if not snapshot:
                logger.error(f"Snapshot {current_id} not found in lookup table")
                break
                
            if not snapshot.metadata:
                # Reached root (no metadata = no parent)
                break
                
            parent_id = snapshot.metadata.get("parent_snapshot_id")
            if not parent_id:
                # Reached root (no parent ID)
                break
                
            # Check if parent exists
            if parent_id not in self.snapshot_lookup:
                logger.warning(f"Broken chain: {current_id} points to non-existent parent {parent_id}")
                classification.broken_chains.add(current_id)
                break
                
            current_id = parent_id
        
        # Check for max depth exceeded (potential infinite loop)
        if len(visited_in_chain) >= self.max_traversal_depth:
            logger.error(f"Max traversal depth exceeded starting from {snapshot_id}. "
                        f"Chain: {' → '.join(visited_in_chain[-10:])}")
    
    def get_cleanup_candidates(self, classification: SnapshotClassification) -> List[str]:
        """
        Get list of snapshot IDs that are safe to delete.
        
        Args:
            classification: Result from classify_snapshots()
            
        Returns:
            List of snapshot IDs that can be safely deleted
        """
        candidates = list(classification.unreachable)
        
        # Add broken chain snapshots (orphaned children)
        candidates.extend(classification.broken_chains)
        
        logger.info(f"Found {len(candidates)} cleanup candidates")
        return candidates
    
    def validate_cleanup_safety(self, candidates: List[str], classification: SnapshotClassification) -> Tuple[List[str], List[str]]:
        """
        Validate that cleanup candidates are safe to delete.
        
        Args:
            candidates: List of snapshot IDs to validate
            classification: Classification result
            
        Returns:
            Tuple of (safe_to_delete, unsafe_to_delete)
        """
        safe_to_delete = []
        unsafe_to_delete = []
        
        for candidate_id in candidates:
            if candidate_id in classification.gc_roots:
                logger.error(f"SAFETY VIOLATION: {candidate_id} is a GC root but marked for deletion!")
                unsafe_to_delete.append(candidate_id)
            elif candidate_id in classification.reachable:
                logger.error(f"SAFETY VIOLATION: {candidate_id} is reachable but marked for deletion!")
                unsafe_to_delete.append(candidate_id)
            else:
                safe_to_delete.append(candidate_id)
        
        if unsafe_to_delete:
            logger.error(f"Found {len(unsafe_to_delete)} unsafe deletion candidates! "
                        f"This indicates a bug in the GC logic.")
        
        return safe_to_delete, unsafe_to_delete
    
    def analyze_snapshot_tree(self, snapshots: List[Snapshot]) -> Dict[str, any]:
        """
        Analyze the snapshot tree structure for debugging and insights.
        
        Args:
            snapshots: List of all snapshots
            
        Returns:
            Dictionary with tree analysis metrics
        """
        self.snapshot_lookup = {s.id: s for s in snapshots}
        
        analysis = {
            "total_snapshots": len(snapshots),
            "root_snapshots": 0,
            "leaf_snapshots": 0,
            "branch_points": 0,
            "max_chain_length": 0,
            "orphaned_snapshots": 0,
            "tagged_snapshots": 0,
            "parent_child_relationships": 0
        }
        
        # Build parent-child relationship map
        children_map = {}  # parent_id -> [child_ids]
        parent_map = {}    # child_id -> parent_id
        
        for snapshot in snapshots:
            if snapshot.metadata and snapshot.metadata.get("parent_snapshot_id"):
                parent_id = snapshot.metadata["parent_snapshot_id"]
                parent_map[snapshot.id] = parent_id
                
                if parent_id not in children_map:
                    children_map[parent_id] = []
                children_map[parent_id].append(snapshot.id)
                analysis["parent_child_relationships"] += 1
        
        # Analyze snapshot characteristics
        for snapshot in snapshots:
            # Root snapshots (no parent)
            if snapshot.id not in parent_map:
                analysis["root_snapshots"] += 1
            
            # Leaf snapshots (no children)
            if snapshot.id not in children_map:
                analysis["leaf_snapshots"] += 1
            
            # Branch points (multiple children)
            if snapshot.id in children_map and len(children_map[snapshot.id]) > 1:
                analysis["branch_points"] += 1
            
            # Tagged snapshots
            if snapshot.metadata and snapshot.metadata.get("tag"):
                analysis["tagged_snapshots"] += 1
            
            # Orphaned snapshots (parent doesn't exist)
            if snapshot.id in parent_map:
                parent_id = parent_map[snapshot.id]
                if parent_id not in self.snapshot_lookup:
                    analysis["orphaned_snapshots"] += 1
        
        # Find maximum chain length
        for snapshot in snapshots:
            if snapshot.id not in parent_map:  # Start from roots
                chain_length = self._calculate_chain_length(snapshot.id, children_map)
                analysis["max_chain_length"] = max(analysis["max_chain_length"], chain_length)
        
        return analysis
    
    def _calculate_chain_length(self, snapshot_id: str, children_map: Dict[str, List[str]]) -> int:
        """Calculate the maximum chain length from a given snapshot."""
        if snapshot_id not in children_map:
            return 1  # Leaf node
        
        max_child_length = 0
        for child_id in children_map[snapshot_id]:
            child_length = self._calculate_chain_length(child_id, children_map)
            max_child_length = max(max_child_length, child_length)
        
        return 1 + max_child_length