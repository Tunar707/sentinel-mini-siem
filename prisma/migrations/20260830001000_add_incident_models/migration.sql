CREATE TABLE "Incident" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "logId" TEXT NOT NULL UNIQUE,
    "status" TEXT NOT NULL DEFAULT 'New',
    "assignedAnalyst" TEXT NOT NULL DEFAULT 'Tunar',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Incident_logId_fkey" FOREIGN KEY ("logId") REFERENCES "Log"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE "IncidentNote" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "incidentId" TEXT NOT NULL,
    "analyst" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "IncidentNote_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE INDEX "Incident_logId_idx"
    ON "Incident"("logId");

CREATE INDEX "IncidentNote_incidentId_idx"
    ON "IncidentNote"("incidentId");
