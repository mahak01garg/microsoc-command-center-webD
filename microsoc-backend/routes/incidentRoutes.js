const express = require("express");
const router = express.Router();
const Incident = require("../models/Incident");
const { protect } = require("../middleware/auth");

// CREATE incident (admin only)
router.post("/", protect, async (req, res) => {
    try {
        if (req.user.role !== "admin") {
            return res.status(403).json({ message: "Only admins can create incidents." });
        }

        const incident = await Incident.create({
            title: req.body.title,
            description: req.body.description,
            severity: req.body.severity,
            status: req.body.status || "open",
            sourceIP: req.body.sourceIP,
            affectedSystems: req.body.affectedSystems || [],
            tags: req.body.tags || [],
            category: req.body.category || "other",
            priority: req.body.priority || req.body.severity || "medium",
            impact: req.body.impact || req.body.severity || "medium",
            createdBy: req.user.id
        });

        res.json({ success: true, incident });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// GET all incidents
router.get("/", protect, async (req, res) => {
    const query = req.user.role === 'admin'
        ? {}
        : { $or: [{ assignedTo: req.user.id }, { createdBy: req.user.id }] };
    const incidents = await Incident.find(query).sort({ createdAt: -1 });
    res.json({ success: true, incidents });
});

module.exports = router;
