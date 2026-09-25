from fastapi import APIRouter

from app.database.connection import get_database_connection

router = APIRouter()


@router.get("/incidents")
def get_incidents():

    conn = get_database_connection()

    try:
        with conn.cursor() as cursor:

            cursor.execute("""
                SELECT id, title, severity, status
                FROM incidents
                ORDER BY id DESC
            """)

            rows = cursor.fetchall()

        return {
            "incidents": [
                {
                    "id": row[0],
                    "title": row[1],
                    "severity": row[2],
                    "status": row[3]
                }
                for row in rows
            ]
        }

    finally:
        conn.close()
