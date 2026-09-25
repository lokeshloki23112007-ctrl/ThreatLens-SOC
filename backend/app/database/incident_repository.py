from app.database.connection import get_database_connection


def create_incident(
    incident_id: str,
    title: str,
    severity: str,
    status: str
):
    conn = get_database_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO incidents
                (id, title, severity, status)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    incident_id,
                    title,
                    severity,
                    status
                )
            )

        conn.commit()

    finally:
        conn.close()
