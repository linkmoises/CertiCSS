#!/usr/bin/env python3
"""
Test script for the check-in system functionality
"""

from pymongo import MongoClient
from datetime import datetime
import sys

def test_checkin_system():
    """Test the check-in system database operations"""
    
    try:
        # Connect to MongoDB (using same config as app)
        client = MongoClient('mongodb://localhost:27017/')
        db = client['certi_css']
        collection_participantes_temporales = db['participantes_temporales']
        
        print("✅ Connected to MongoDB successfully")
        
        # Test data
        test_participant = {
            'nombres': 'Juan Carlos',
            'apellidos': 'Pérez González',
            'cedula': '8-123-456',
            'perfil': 'medico_general',
            'region': 'panama',
            'unidad': 'Hospital Nacional',
            'codigo_evento': 'TEST001',
            'timestamp': datetime.now(),
            'asistencia_confirmada': False,
            'material_entregado': False,
            'fecha_checkin': None
        }
        
        # Insert test participant
        result = collection_participantes_temporales.insert_one(test_participant)
        print(f"✅ Test participant inserted with ID: {result.inserted_id}")
        
        # Query test participant
        found_participant = collection_participantes_temporales.find_one({
            'codigo_evento': 'TEST001',
            'cedula': '8-123-456'
        })
        
        if found_participant:
            print("✅ Test participant found successfully")
            print(f"   Name: {found_participant['nombres']} {found_participant['apellidos']}")
            print(f"   Profile: {found_participant['perfil']}")
        else:
            print("❌ Test participant not found")
            return False
        
        # Update test participant
        collection_participantes_temporales.update_one(
            {"_id": found_participant["_id"]},
            {"$set": {
                "asistencia_confirmada": True,
                "material_entregado": True,
                "fecha_checkin": datetime.now()
            }}
        )
        print("✅ Test participant updated successfully")
        
        # Clean up test data
        collection_participantes_temporales.delete_one({"_id": found_participant["_id"]})
        print("✅ Test data cleaned up")
        
        # Test collection stats
        total_count = collection_participantes_temporales.count_documents({})
        print(f"✅ Total participants in collection: {total_count}")
        
        print("\n🎉 All check-in system tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Error testing check-in system: {str(e)}")
        return False
    
    finally:
        if 'client' in locals():
            client.close()

if __name__ == "__main__":
    success = test_checkin_system()
    sys.exit(0 if success else 1)