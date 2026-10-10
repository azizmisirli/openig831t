# SPDX-License-Identifier: Apache-2.0
"""Synthetic offline session/fault tests; no hardware or transport APIs."""
from dataclasses import replace
import unittest
from igbridge.errors import ConfigurationError, ProtocolError
from igbridge.qmi import TLV, parse_message, build_message
from igbridge.qmi_session import QmiSession, ResponseQueue
OK=TLV(2,b"\0\0\0\0")
ERROR=TLV(2,b"\x01\x00\x4a\x00")

def response(request, tlvs=(OK,), **overrides):
    return replace(parse_message(request),kind="response",tlvs=tuple(tlvs),**overrides).to_bytes()

def allocate(session, service=2, backend_cid=17, host_tid=80, now=0):
    wire=session.host_to_backend(build_message(0,0,host_tid,0x22,tlvs=(TLV(1,bytes((service,))),)),now=now)
    frontend=session.backend_to_host(response(wire,(OK,TLV(1,bytes((service,backend_cid))),TLV(0x99,b"opaque"))),now=now)
    return parse_message(frontend).tlv(1)[1]

def release_request(cid,tid=91,service=2):
    return build_message(0,0,tid,0x23,tlvs=(TLV(1,bytes((service,cid))),))

class SessionTests(unittest.TestCase):
    def test_passthrough_default_preserves_bytes(self):
        s=QmiSession(); req=build_message(0,0,2,0x21,tlvs=(TLV(255,b"unknown"),))
        self.assertEqual(s.host_to_backend(req,now=0),req)
        raw=response(req,(TLV(255,b"\xff\x00"),OK))
        self.assertEqual(s.backend_to_host(raw,now=0),raw); self.assertEqual(s.pending_count,0)

    def test_allocate_success_commit_and_remap(self):
        s=QmiSession(mode="remap")
        wire=s.host_to_backend(build_message(0,0,9,0x22,tlvs=(TLV(1,b"\2"),)),now=0)
        self.assertEqual(s.clients,()); self.assertEqual(parse_message(wire).transaction_id,1)
        host=parse_message(s.backend_to_host(response(wire,(OK,TLV(1,b"\2\x45"),TLV(170,b"same"))),now=1))
        self.assertEqual((host.transaction_id,host.tlv(1),host.tlv(170)),(9,b"\2\1",b"same"))
        self.assertEqual((s.clients[0].host_cid,s.clients[0].backend_cid),(1,69))

    def test_failed_allocate_preserves_error_no_binding(self):
        s=QmiSession(mode="remap")
        wire=s.host_to_backend(build_message(0,0,9,0x22,tlvs=(TLV(1,b"\2"),)),now=0)
        raw=response(wire,(ERROR,TLV(160,b"diagnostic")))
        self.assertEqual(parse_message(s.backend_to_host(raw,now=0)).tlvs,parse_message(raw).tlvs)
        self.assertEqual(s.clients,()); self.assertEqual(s.pending_count,0)

    def test_bad_allocation_never_mutates(self):
        for info in (b"",b"\2",b"\3\1",b"\2\0",b"\2\xff"):
            s=QmiSession(mode="remap")
            wire=s.host_to_backend(build_message(0,0,9,0x22,tlvs=(TLV(1,b"\2"),)),now=0)
            with self.subTest(info=info),self.assertRaises(ProtocolError):
                s.backend_to_host(response(wire,(OK,TLV(1,info))),now=0)
            self.assertEqual(s.clients,()); self.assertEqual(s.pending_count,1)

    def test_service_tid_cid_remap_payload_unchanged(self):
        s=QmiSession(mode="remap"); cid=allocate(s)
        req=build_message(2,cid,0xabcd,0x21,tlvs=(TLV(250,b"unchanged"),))
        wire=s.host_to_backend(req,now=1); m=parse_message(wire)
        self.assertEqual((m.cid,m.transaction_id),(17,1)); self.assertEqual(wire[9:],req[9:])
        raw=response(wire,(OK,TLV(241,b"reply"))); out=parse_message(s.backend_to_host(raw,now=2))
        self.assertEqual((out.cid,out.transaction_id),(1,0xabcd)); self.assertEqual(out.tlvs,parse_message(raw).tlvs)

    def test_default_service_has_no_rewrite(self):
        s=QmiSession(); cid=allocate(s); self.assertEqual(cid,17)
        req=build_message(2,cid,0xf123,0x21)
        self.assertEqual(s.host_to_backend(req,now=0),req)
        raw=response(req,(ERROR,));self.assertEqual(s.backend_to_host(raw,now=0),raw)

    def test_release_success_commit_and_payload_mapping(self):
        s=QmiSession(mode="remap");cid=allocate(s)
        wire=s.host_to_backend(release_request(cid),now=1)
        self.assertEqual(parse_message(wire).tlv(1),b"\2\x11");self.assertEqual(len(s.clients),1)
        raw=response(wire,(OK,TLV(1,b"\2\x11"),TLV(250,b"keep")))
        host=parse_message(s.backend_to_host(raw,now=1))
        self.assertEqual((host.tlv(1),host.transaction_id,host.tlv(250)),(b"\2\1",91,b"keep"))
        self.assertEqual(s.clients,())

    def test_release_error_retains_binding(self):
        s=QmiSession(mode="remap");cid=allocate(s)
        wire=s.host_to_backend(release_request(cid),now=1)
        s.backend_to_host(response(wire,(ERROR,)),now=1)
        self.assertEqual(len(s.clients),1);s.host_to_backend(build_message(2,cid,1,0x21),now=2)

    def test_release_bad_response_retains_binding(self):
        s=QmiSession();cid=allocate(s);wire=s.host_to_backend(release_request(cid),now=0)
        with self.assertRaises(ProtocolError):s.backend_to_host(response(wire,(OK,TLV(1,b"\2\x12"))),now=0)
        self.assertEqual(len(s.clients),1)

    def test_release_query_interlock(self):
        s=QmiSession();cid=allocate(s);wire=s.host_to_backend(build_message(2,cid,1,0x21),now=0)
        with self.assertRaises(ProtocolError):s.host_to_backend(release_request(cid),now=0)
        s.backend_to_host(response(wire),now=0);s.host_to_backend(release_request(cid),now=0)
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(2,cid,2,0x21),now=0)
        with self.assertRaises(ProtocolError):s.host_to_backend(release_request(cid,92),now=0)

    def test_indication_mapping_broadcast_and_unknown_cid(self):
        s=QmiSession(mode="remap");cid=allocate(s)
        raw=build_message(2,17,0,0x25,"indication",(TLV(255,b"opaque"),))
        mapped=parse_message(s.backend_to_host(raw,now=0))
        self.assertEqual(mapped.cid,cid);self.assertEqual(mapped.tlvs,parse_message(raw).tlvs)
        broadcast=build_message(2,255,0,0x25,"indication",(TLV(255,b"opaque"),))
        self.assertEqual(s.backend_to_host(broadcast,now=0),broadcast)
        with self.assertRaises(ProtocolError):s.backend_to_host(build_message(3,255,0,0x25,"indication"),now=0)
        with self.assertRaises(ProtocolError):s.backend_to_host(build_message(2,18,0,0x25,"indication"),now=0)

    def test_sync_does_not_complete_version_request(self):
        s=QmiSession(mode="remap");s.host_to_backend(build_message(0,0,9,0x21),now=0)
        sync=bytes.fromhex("010b00800000020027000000")
        self.assertEqual(s.backend_to_host(sync,now=0),sync);self.assertEqual(s.pending_count,1)
        self.assertTrue(s.sync_invalidated)
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(0,0,10,0x21),now=0)
        self.assertTrue(s.disconnect()["sync_invalidated"])

    def test_initial_sync_does_not_invalidate_empty_session(self):
        s=QmiSession();sync=bytes.fromhex("010b00800000020027000000")
        self.assertEqual(s.backend_to_host(sync,now=0),sync)
        self.assertFalse(s.sync_invalidated)
        s.host_to_backend(build_message(0,0,1,0x21),now=0)

    def test_mid_session_sync_blocks_cleanup_and_stale_indications(self):
        s=QmiSession(mode="remap");allocate(s)
        s.backend_to_host(bytes.fromhex("010b00800000020027000000"),now=0)
        with self.assertRaises(ProtocolError):s.cleanup_requests(now=0)
        with self.assertRaises(ProtocolError):s.backend_to_host(build_message(2,17,0,0x25,"indication"),now=0)
        report=s.disconnect();self.assertTrue(report["sync_invalidated"])
        self.assertEqual(len(report["known_backend_clients"]),1)
        s.reconnect(transport_flushed=True);self.assertFalse(s.sync_invalidated)

    def test_opaque_ctl_remap_rejected_passthrough_preserved(self):
        raw=build_message(0,0,0,0x24,"indication",(TLV(1,b"opaque"),))
        with self.assertRaises(ProtocolError):QmiSession(mode="remap").backend_to_host(raw,now=0)
        self.assertEqual(QmiSession().backend_to_host(raw,now=0),raw)
        with self.assertRaises(ProtocolError):QmiSession(mode="remap").host_to_backend(build_message(0,0,1,0xff00),now=0)

    def test_exact_matching_and_duplicate_response(self):
        s=QmiSession(mode="remap");cid=allocate(s);wire=s.host_to_backend(build_message(2,cid,9,0x21),now=0)
        for kwargs in ({"service":3},{"cid":18},{"transaction_id":2},{"message_id":0x22}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ProtocolError):s.backend_to_host(response(wire,**kwargs),now=0)
        self.assertEqual(s.pending_count,1);s.backend_to_host(response(wire),now=0)
        with self.assertRaises(ProtocolError):s.backend_to_host(response(wire),now=0)

    def test_unknown_cid_zero_tid_direction_duplicate_tid(self):
        s=QmiSession()
        for raw in (build_message(2,1,1,0x21),build_message(0,0,0,0x21),build_message(0,0,1,0x21,"response")):
            with self.assertRaises(ProtocolError):s.host_to_backend(raw,now=0)
        req=build_message(0,0,1,0x21);s.host_to_backend(req,now=0)
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(0,0,1,0x27),now=0)
        with self.assertRaises(ProtocolError):s.backend_to_host(req,now=0)

    def test_timeout_deadline_and_late_response_quarantine(self):
        s=QmiSession(timeout=3);req=build_message(0,0,1,0x21);s.host_to_backend(req,now=0)
        self.assertEqual(s.expire(now=2.999),[]);self.assertEqual(len(s.expire(now=3)),1)
        self.assertEqual(s.pending_count,0)
        with self.assertRaises(ProtocolError):s.backend_to_host(response(req),now=3)
        with self.assertRaises(ProtocolError):s.host_to_backend(req,now=3)
        self.assertEqual(s.timeout_count,1)

    def test_remap_host_tid_reuse_never_matches_timed_out_backend_tid(self):
        s=QmiSession(mode="remap",timeout=1);req=build_message(0,0,8,0x21)
        old=s.host_to_backend(req,now=0);s.expire(now=1);new=s.host_to_backend(req,now=1)
        self.assertNotEqual(parse_message(old).transaction_id,parse_message(new).transaction_id)
        with self.assertRaises(ProtocolError):s.backend_to_host(response(old),now=1)
        self.assertEqual(parse_message(s.backend_to_host(response(new),now=1)).transaction_id,8)

    def test_allocate_timeout_is_unknown_without_invented_cid(self):
        s=QmiSession(timeout=1);s.host_to_backend(build_message(0,0,1,0x22,tlvs=(TLV(1,b"\2"),)),now=0)
        events=s.expire(now=1);self.assertTrue(events[0]["backend_allocation_unknown"])
        out=s.disconnect();self.assertEqual(out["unresolved_allocation_requests"],1)
        self.assertEqual(out["known_backend_clients"],[]);self.assertFalse(out["backend_cleanup_performed"])

    def test_release_timeout_freezes_cid_cleanup_metadata_only(self):
        s=QmiSession(timeout=1);cid=allocate(s);s.host_to_backend(release_request(cid),now=0);s.expire(now=1)
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(2,cid,1,0x21),now=1)
        out=s.disconnect();self.assertTrue(out["known_backend_clients"][0]["release_outcome_unknown"])
        self.assertEqual(out["known_backend_clients"][0]["backend_cid"],17)

    def test_disconnect_and_flush_reconnect(self):
        s=QmiSession();cid=allocate(s);s.host_to_backend(build_message(2,cid,1,0x21),now=0)
        out=s.disconnect();self.assertEqual(out["abandoned_requests"],1);self.assertEqual(len(out["known_backend_clients"]),1)
        self.assertEqual(s.clients,());self.assertEqual(s.pending_count,0)
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(0,0,1,0x21),now=0)
        with self.assertRaises(ProtocolError):s.reconnect()
        s.reconnect(transport_flushed=True);self.assertEqual(s.generation,1)
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(2,cid,1,0x21),now=0)
        s.host_to_backend(build_message(0,0,1,0x21),now=0)

    def test_pending_capacity_and_allocate_reservations(self):
        s=QmiSession(max_pending=1);s.host_to_backend(build_message(0,0,1,0x21),now=0)
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(0,0,2,0x21),now=0)
        s=QmiSession(max_clients=1);s.host_to_backend(build_message(0,0,1,0x22,tlvs=(TLV(1,b"\2"),)),now=0)
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(0,0,2,0x22,tlvs=(TLV(1,b"\3"),)),now=0)

    def test_quarantine_capacity_blocks_without_unbounded_growth(self):
        s=QmiSession(timeout=1,max_quarantined=1)
        for n in (1,2):s.host_to_backend(build_message(0,0,n,0x21),now=n-1);s.expire(now=n)
        self.assertTrue(s.quarantine_exhausted);self.assertEqual(len(s._quarantined),1)
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(0,0,3,0x21),now=2)

    def test_ctl_tid_exhaustion_bounded_timeout_history(self):
        s=QmiSession(mode="remap",timeout=1);req=build_message(0,0,1,0x21)
        for tid in range(1,256):
            self.assertEqual(parse_message(s.host_to_backend(req,now=tid-1)).transaction_id,tid);s.expire(now=tid)
        with self.assertRaises(ProtocolError):s.host_to_backend(req,now=255)
        self.assertEqual(len(s.timeout_events),64);self.assertEqual(s.timeout_count,255)

    def test_successful_tid_wrap(self):
        s=QmiSession(mode="remap")
        for tid in list(range(1,256))+[1]:
            wire=s.host_to_backend(build_message(0,0,77,0x21),now=0)
            self.assertEqual(parse_message(wire).transaction_id,tid);s.backend_to_host(response(wire),now=0)

    def test_cids_service_scoped_and_duplicate_backend_cid_rejected(self):
        s=QmiSession(mode="remap");self.assertEqual(allocate(s,2,17,1),1);self.assertEqual(allocate(s,3,17,2),1)
        self.assertEqual(len(s.clients),2)
        wire=s.host_to_backend(build_message(0,0,3,0x22,tlvs=(TLV(1,b"\2"),)),now=0)
        with self.assertRaises(ProtocolError):s.backend_to_host(response(wire,(OK,TLV(1,b"\2\x11"))),now=0)
        self.assertEqual(len(s.clients),2)

    def test_invalid_lifecycle_fields(self):
        for mid,info in ((0x22,b""),(0x22,b"\0"),(0x22,b"\2\1"),(0x23,b"\2"),(0x23,b"\0\1")):
            with self.subTest(mid=mid,info=info),self.assertRaises(ProtocolError):
                QmiSession().host_to_backend(build_message(0,0,1,mid,tlvs=(TLV(1,info),)),now=0)

    def test_invalid_configuration_time_and_reconnect(self):
        for kwargs in ({"mode":"magic"},{"max_pending":0},{"timeout":float("nan")},{"timeout":0},{"max_clients":True},{"clock":3}):
            with self.assertRaises(ConfigurationError):QmiSession(**kwargs)
        s=QmiSession();s.expire(now=3)
        for bad in (2,float("nan"),float("inf"),True):
            with self.assertRaises(ProtocolError):s.expire(now=bad)
        with self.assertRaises(ProtocolError):s.reconnect(transport_flushed=True)

class CleanupTests(unittest.TestCase):
    def test_cleanup_only_owned_then_release_ack(self):
        s=QmiSession(mode="remap")
        self.assertEqual(s.cleanup_requests(now=0),())
        allocate(s,2,17,1);allocate(s,3,19,2)
        plans=s.cleanup_requests(now=0)
        self.assertEqual(len(plans),2)
        self.assertEqual(s.cleanup_requests(now=0),())
        self.assertEqual({parse_message(p).transaction_id for p in plans},{254,255})
        self.assertEqual({parse_message(p).tlv(1) for p in plans},{bytes((2,1)),bytes((3,1))})
        for plan in plans:
            self.assertEqual(parse_message(plan).message_id,0x23)
            wire=s.host_to_backend(plan,now=0)
            info=parse_message(wire).tlv(1)
            self.assertIn(info,(bytes((2,17)),bytes((3,19))))
            s.backend_to_host(response(wire,(OK,TLV(1,info))),now=0)
        self.assertEqual(s.clients,())
        self.assertEqual(s.disconnect()["known_backend_clients"],[])

    def test_cleanup_pending_query_skipped_until_expiry(self):
        s=QmiSession(timeout=1);cid=allocate(s)
        s.host_to_backend(build_message(2,cid,1,0x21),now=0)
        self.assertEqual(s.cleanup_requests(now=0),())
        plans=s.cleanup_requests(now=1)
        self.assertEqual(len(plans),1)
        self.assertEqual(parse_message(plans[0]).tlv(1),bytes((2,cid)))

    def test_cleanup_skips_uncertain_or_inflight_release(self):
        s=QmiSession(timeout=1);cid=allocate(s)
        s.host_to_backend(release_request(cid),now=0)
        self.assertEqual(s.cleanup_requests(now=0),())
        self.assertEqual(s.cleanup_requests(now=1),())
        self.assertTrue(s.disconnect()["known_backend_clients"][0]["release_outcome_unknown"])

    def test_cleanup_error_does_not_auto_retry(self):
        s=QmiSession();allocate(s)
        plan=s.cleanup_requests(now=0)[0]
        wire=s.host_to_backend(plan,now=0)
        s.backend_to_host(response(wire,(ERROR,)),now=0)
        self.assertEqual(s.cleanup_requests(now=0),())
        self.assertEqual(len(s.disconnect()["known_backend_clients"]),1)

    def test_cleanup_reserves_host_transaction_and_capacity(self):
        s=QmiSession(max_pending=1);allocate(s)
        plan=s.cleanup_requests(now=0)[0];tid=parse_message(plan).transaction_id
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(0,0,tid,0x21),now=0)
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(0,0,tid-1,0x21),now=0)
        self.assertEqual(s.host_to_backend(plan,now=0),plan)

    def test_cleanup_avoids_quarantined_ctl_tid_and_pending_tid(self):
        s=QmiSession(timeout=1);allocate(s)
        s.host_to_backend(build_message(0,0,255,0x21),now=0);s.expire(now=1)
        s.host_to_backend(build_message(0,0,254,0x21),now=1)
        plan=s.cleanup_requests(now=1)[0]
        self.assertEqual(parse_message(plan).transaction_id,253)

    def test_cleanup_reservation_is_not_claimed_sent(self):
        s=QmiSession();allocate(s);s.cleanup_requests(now=0)
        report=s.disconnect()
        self.assertEqual(report["planned_unsent_cleanup_requests"],1)
        self.assertEqual(report["unresolved_release_requests"],0)
        self.assertFalse(report["backend_cleanup_performed"])

    def test_old_cleanup_plan_cannot_release_reallocated_host_cid(self):
        s=QmiSession(mode="remap")
        allocate(s,backend_cid=17,host_tid=1)
        old=s.cleanup_requests(now=0)[0]
        manual=s.host_to_backend(release_request(1,2),now=0)
        s.backend_to_host(response(manual,(OK,TLV(1,bytes((2,17))))),now=0)
        allocate(s,backend_cid=18,host_tid=3)
        with self.assertRaises(ProtocolError):s.host_to_backend(old,now=0)
        self.assertEqual((s.clients[0].host_cid,s.clients[0].backend_cid),(1,18))
        self.assertEqual(s.pending_count,0)

    def test_stale_cleanup_plan_rejected_when_backend_also_reuses_same_cid(self):
        s=QmiSession(mode="remap")
        allocate(s,backend_cid=17,host_tid=1);old=s.cleanup_requests(now=0)[0]
        wire=s.host_to_backend(release_request(1,2),now=0)
        s.backend_to_host(response(wire,(OK,TLV(1,bytes((2,17))))),now=0)
        allocate(s,backend_cid=17,host_tid=3)
        with self.assertRaises(ProtocolError):s.host_to_backend(old,now=0)
        self.assertEqual(s.pending_count,0)
        self.assertEqual(len(s.clients),1)

    def test_consumed_cleanup_plan_cannot_be_replayed_on_new_owner(self):
        s=QmiSession(mode="remap")
        allocate(s,host_tid=1);old=s.cleanup_requests(now=0)[0]
        wire=s.host_to_backend(old,now=0)
        s.backend_to_host(response(wire,(OK,TLV(1,bytes((2,17))))),now=0)
        allocate(s,backend_cid=18,host_tid=2)
        with self.assertRaises(ProtocolError):s.host_to_backend(old,now=0)
        self.assertEqual(s.clients[0].backend_cid,18)

    def test_old_cleanup_plan_cannot_cross_reconnect_generation(self):
        s=QmiSession(mode="remap")
        allocate(s,host_tid=1);old=s.cleanup_requests(now=0)[0]
        s.disconnect();s.reconnect(transport_flushed=True)
        allocate(s,backend_cid=18,host_tid=1)
        with self.assertRaises(ProtocolError):s.host_to_backend(old,now=0)
        fresh=s.cleanup_requests(now=0)[0]
        self.assertNotEqual(parse_message(old).transaction_id,parse_message(fresh).transaction_id)
        self.assertEqual(parse_message(s.host_to_backend(fresh,now=0)).tlv(1),bytes((2,18)))

    def test_cleanup_retirement_is_bounded_and_never_recycles(self):
        s=QmiSession()
        for expected_tid in range(255,0,-1):
            allocate(s,host_tid=1)
            plan=s.cleanup_requests(now=0)[0]
            self.assertEqual(parse_message(plan).transaction_id,expected_tid)
            wire=s.host_to_backend(plan,now=0)
            s.backend_to_host(response(wire,(OK,TLV(1,bytes((2,17))))),now=0)
        self.assertEqual(len(s._cleanup_retired),255)
        self.assertEqual(s.cleanup_requests(now=0),())
        with self.assertRaises(ProtocolError):s.host_to_backend(build_message(0,0,1,0x21),now=0)

    def test_reallocated_client_can_be_cleaned_as_new_owner(self):
        s=QmiSession();allocate(s,host_tid=1)
        plan=s.cleanup_requests(now=0)[0];wire=s.host_to_backend(plan,now=0)
        s.backend_to_host(response(wire,(OK,TLV(1,bytes((2,17))))),now=0)
        allocate(s,host_tid=2)
        self.assertEqual(len(s.cleanup_requests(now=0)),1)

class QueueTests(unittest.TestCase):
    def test_fifo_and_host_notification_metadata(self):
        q=ResponseQueue();a=build_message(0,0,0,0x27,"indication");b=build_message(0,0,1,0x21,"response",(OK,))
        self.assertFalse(q.notification_metadata(4)["response_available"]);q.enqueue(a);q.enqueue(b)
        self.assertEqual(q.notification_metadata(7),{"generation":0,"response_available":True,"host_interface":7,"queued_messages":2,"queued_bytes":len(a)+len(b),"next_length":len(a)})
        self.assertEqual(q.pop(4096),a);self.assertEqual(q.pop(4096),b);self.assertEqual(q.pop(4096),b"");self.assertEqual(q.byte_count,0)

    def test_short_get_keeps_whole_frame(self):
        q=ResponseQueue();raw=build_message(0,0,0,0x27,"indication");q.enqueue(raw)
        with self.assertRaises(ProtocolError):q.pop(len(raw)-1)
        self.assertEqual(q.byte_count,len(raw));self.assertEqual(q.pop(len(raw)),raw)

    def test_limits_clear_request_rejection(self):
        raw=build_message(0,0,0,0x27,"indication")
        for q in (ResponseQueue(max_messages=1),ResponseQueue(max_bytes=12)):
            q.enqueue(raw)
            with self.assertRaises(ProtocolError):q.enqueue(raw)
            self.assertEqual(q.byte_count,12);q.clear();self.assertEqual(q.notification_metadata(4)["generation"],1)
            self.assertEqual(q.pop(4096),b"")
        with self.assertRaises(ProtocolError):ResponseQueue().enqueue(build_message(0,0,1,0x21))

    def test_invalid_parameters(self):
        with self.assertRaises(ConfigurationError):ResponseQueue(max_messages=0)
        for value in (-1,True,"4",256):
            with self.assertRaises(ProtocolError):ResponseQueue().notification_metadata(value)
        for value in (-1,True,"4096"):
            with self.assertRaises(ProtocolError):ResponseQueue().pop(value)

if __name__ == "__main__":unittest.main()
