import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { ContactShadows } from '@react-three/drei/core/ContactShadows.js';
import { Edges } from '@react-three/drei/core/Edges.js';
import { OrbitControls } from '@react-three/drei/core/OrbitControls.js';
import { RoundedBox } from '@react-three/drei/core/RoundedBox.js';
import { Html } from '@react-three/drei/web/Html.js';
import { Activity, AlertTriangle, Box, Building2, Check, ChevronRight, Clock3, Filter, Layers3, MapPin, Maximize2, Minimize2, PackageSearch, Pause, Play, RotateCcw, Search, Sparkles, Wrench, X } from 'lucide-react';
import { CAMPUS_BUILDINGS, SPACE_ASSETS } from './campus-model.js';
import './digital-twin.css';

const SKETCHFAB_CLASSROOM = 'classroom-d4553cc2008242849214e4cbf8ad8551';

const campusRoomRef = (room) => {
  const building = CAMPUS_BUILDINGS.find((item) => item.id === 'academic-block-a') || CAMPUS_BUILDINGS[0];
  const floor = building.floors.find((item) => item.number === room.floor);
  const campusRoom = floor?.rooms.find((item) => item.name === room.name);
  return { buildingId: building.id, buildingName: building.name, floor: String(room.floor), floorName: floor?.name || room.floorName, roomId: campusRoom?.id || '', roomName: room.name, spaceType: campusRoom?.type || room.type };
};

const FLOOR_BLUEPRINTS = [
  { number: 1, name: 'Ground & foyer', rooms: ['Foyer', 'Seating Lounge', 'Reception', 'Security Desk', 'Admin Office', 'Principal Cabin', 'Staff Office', 'Medical Room', 'Washroom (Male)', 'Washroom (Female)'] },
  { number: 2, name: 'First floor', rooms: ['Office Suite', 'Seminar Hall', 'Library', 'Computer Lab', 'Classroom 201', 'Classroom 202', 'Classroom 203', 'Classroom 204', 'Washroom (Male)', 'Washroom (Female)'] },
  { number: 3, name: 'Classrooms & labs', rooms: ['Classroom 301', 'Classroom 302', 'Classroom 303', 'Classroom 304', 'Computer Lab 2', 'Electronics Lab', 'Server / Network Room', 'Faculty Cabin', 'Washroom (Male)', 'Washroom (Female)'] },
  { number: 4, name: 'Science & innovation', rooms: ['Classroom 401', 'Classroom 402', 'Classroom 403', 'Classroom 404', 'Electronics Lab', 'IoT / Robotics Lab', 'Innovation / Project Lab', 'Equipment Storage', 'Washroom (Male)', 'Washroom (Female)'] },
  { number: 5, name: 'Library & study', rooms: ['Classroom 501', 'Classroom 502', 'Classroom 503', 'Classroom 504', 'Library', 'Reading Hall', 'Exam Cell', 'Discussion Room', 'Washroom (Male)', 'Washroom (Female)'] },
];

const ROOM_POSITIONS = [
  [-8, -3.25], [-4, -3.25], [0, -3.25], [4, -3.25], [8, -3.25],
  [-8, 3.25], [-4, 3.25], [0, 3.25], [4, 3.25], [8, 3.25],
];

const ROOM_OVERRIDES = {
  '1:Foyer': { active: 1, resolved: 9, health: 88, category: 'Accessibility · Signage', department: 'Campus Services' },
  '1:Seating Lounge': { active: 0, resolved: 7, health: 92, category: 'Comfort', department: 'Campus Services' },
  '1:Reception': { active: 1, resolved: 8, recurring: 1, health: 88, category: 'Accessibility', lost: 2 },
  '1:Admin Office': { active: 0, resolved: 4, health: 95, category: 'Campus services' },
  '1:Principal Cabin': { active: 0, resolved: 3, health: 97, category: 'Campus services' },
  '2:Seminar Hall': { active: 1, resolved: 6, health: 82, category: 'Audio · Projector', department: 'Academic Operations' },
  '2:Library': { active: 1, resolved: 13, recurring: 0, health: 91, category: 'Lighting', lost: 3 },
  '2:Computer Lab': { active: 2, resolved: 11, recurring: 2, health: 66, category: 'Hardware · Cooling', department: 'IT Support', maintenance: true },
  '2:Classroom 202': { active: 2, resolved: 9, recurring: 1, health: 76, category: 'Furniture · Electrical' },
  '2:Classroom 204': { active: 1, resolved: 6, recurring: 1, health: 84, category: 'Projector · IT' },
  '3:Classroom 302': { active: 4, resolved: 12, recurring: 3, health: 54, category: 'Electrical · Network', department: 'IT Support' },
  '3:Computer Lab 2': { active: 3, resolved: 15, recurring: 2, health: 63, category: 'Hardware · Cooling', department: 'IT Support', maintenance: true },
  '3:Server / Network Room': { active: 2, resolved: 8, recurring: 2, health: 66, category: 'Network · Cooling', department: 'IT Support', maintenance: true },
  '3:Washroom (Male)': { active: 3, resolved: 11, recurring: 3, health: 58, category: 'Plumbing · Cleanliness', department: 'Facilities' },
  '4:Electronics Lab': { active: 3, resolved: 7, recurring: 2, health: 61, category: 'Safety · Electrical', department: 'Safety & Electrical', maintenance: true },
  '4:IoT / Robotics Lab': { active: 1, resolved: 10, recurring: 0, health: 86, category: 'Equipment', department: 'Lab Operations' },
  '5:Library': { active: 1, resolved: 13, recurring: 0, health: 91, category: 'Lighting', lost: 3 },
  '1:Lost & Found Office': { active: 0, resolved: 4, recurring: 0, health: 96, category: 'Campus services', lost: 5 },
};

const TIMELINE = [
  { time: '10:00', floor: 3, title: 'Projector fault reported', detail: 'Classroom 302' },
  { time: '10:08', floor: 3, title: 'Similar network report detected', detail: 'Computer Lab 2' },
  { time: '10:14', floor: 3, title: 'Common root cause suggested', detail: 'Floor 3 network segment' },
  { time: '10:22', floor: 3, title: 'IT Support assigned', detail: 'ETA 45 minutes' },
  { time: '10:41', floor: 4, title: 'Safety inspection started', detail: 'Electronics Lab' },
];

const STATUS_COLORS = {
  healthy: '#55a879',
  watch: '#dfbd52',
  attention: '#ed8b4e',
  critical: '#d9504f',
  inactive: '#9ba9a3',
};

const SHIRTS = ['#2f6d58', '#4a6d9e', '#a0503c', '#5d5a86', '#3d7a8f', '#8a6b3d'];

const roomType = (name) => {
  const value = name.toLowerCase();
  if (value.includes('classroom')) return 'classroom';
  if (value.includes('washroom')) return 'washroom';
  if (value.includes('computer lab')) return 'computer lab';
  if (value.includes('seminar')) return 'seminar hall';
  if (value.includes('foyer')) return 'foyer';
  if (value.includes('lounge')) return 'lounge';
  if (value.includes('library') || value.includes('reading') || value.includes('discussion')) return 'library & study';
  if (value.includes('lab')) return 'laboratory';
  if (value.includes('server')) return 'server room';
  if (value.includes('medical')) return 'medical room';
  if (value.includes('office') || value.includes('cabin') || value.includes('staff') || value.includes('reception')) return 'office';
  if (value.includes('security')) return 'security';
  if (value.includes('lift')) return 'circulation';
  return 'campus service';
};

const defaultDepartment = (type) => type === 'computer lab' || type === 'server room' ? 'IT Support' : type === 'laboratory' ? 'Lab Operations' : type === 'washroom' ? 'Facilities' : type === 'security' ? 'Campus Safety' : type === 'office' ? 'Administration' : 'Academic Operations';
const statusFor = (score) => score >= 90 ? 'healthy' : score >= 75 ? 'watch' : score >= 60 ? 'attention' : 'critical';
const normalize = (value) => String(value || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

function resolveRoom(rooms, location) {
  const normalized = normalize(location);
  const roomNumber = normalized.match(/\b([2-5]\d{2})\b/)?.[1];
  if (roomNumber) return rooms.find((room) => room.name.includes(roomNumber));
  return rooms.find((room) => normalized.includes(normalize(room.name)) || normalize(room.name).includes(normalized));
}

function buildRooms(issues = [], lostFound = []) {
  const rooms = FLOOR_BLUEPRINTS.flatMap((floor) => floor.rooms.map((name, index) => {
    const [x, z] = ROOM_POSITIONS[index];
    const type = roomType(name);
    const seed = (floor.number * 29 + index * 17) % 100;
    const baseActive = seed > 90 ? 2 : seed > 77 ? 1 : 0;
    const base = { active: baseActive, resolved: (floor.number * 3 + index * 2) % 12, recurring: seed > 88 ? 1 : 0, lost: 0, health: 100 - baseActive * 8 - (seed > 88 ? 6 : 0), category: baseActive ? (type === 'classroom' ? 'Furniture · Lighting' : 'General maintenance') : 'No active issue' };
    const override = ROOM_OVERRIDES[`${floor.number}:${name}`] || {};
    const merged = { ...base, ...override };
    return {
      id: `room-${floor.number}-${index + 1}`,
      code: name.match(/\d{3}/)?.[0] || `A${floor.number}-${String(index + 1).padStart(2, '0')}`,
      name, floor: floor.number, floorName: floor.name, type, x, z,
      capacity: type === 'classroom' ? 60 : type === 'computer lab' ? 42 : type === 'seminar hall' ? 150 : type === 'library & study' ? 120 : type === 'foyer' ? 40 : type === 'lounge' ? 60 : 18,
      facilities: type === 'classroom' ? ['Benches', 'Blackboard', 'Ceiling fans', 'Projector'] : type === 'computer lab' ? ['Workstations', 'AC', 'UPS', 'LAN'] : type === 'seminar hall' ? ['Stage', 'Projector', 'PA system', 'AC'] : type === 'library & study' ? ['Bookshelves', 'Reading desks', 'Wi-Fi', 'Silent zone'] : type === 'washroom' ? ['Water supply', 'Ventilation', 'Accessible stall'] : type === 'foyer' ? ['Seating', 'Help desk', 'Display screens', 'Plants'] : type === 'lounge' ? ['Seating', 'Tables', 'Drinking water', 'Wi-Fi'] : type === 'office' ? ['Workstations', 'Meeting table', 'AC', 'Printer'] : ['Wi-Fi', 'Lighting', 'Emergency signage'],
      department: merged.department || defaultDepartment(type),
      lastMaintenance: new Date(2026, 7, 12 + ((floor.number * 4 + index) % 20)).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }),
      lastActivity: merged.active ? new Date().toISOString().slice(0, 10) : new Date(Date.now() - (3 + seed % 24) * 86400000).toISOString().slice(0, 10),
      ...merged,
    };
  }));

  issues.filter((issue) => !['resolved', 'closed'].includes(issue.status)).forEach((issue) => {
    const room = resolveRoom(rooms, issue.location);
    if (!room) return;
    room.active += 1;
    room.health -= issue.priority === 'critical' ? 20 : issue.priority === 'high' ? 14 : issue.priority === 'medium' ? 8 : 5;
    room.category = `${room.category === 'No active issue' ? '' : `${room.category} · `}${issue.category || 'Reported issue'}`;
    if (issue.createdAt) room.lastActivity = String(issue.createdAt).slice(0, 10);
  });
  issues.filter((issue) => ['resolved', 'closed'].includes(issue.status)).forEach((issue) => { const room = resolveRoom(rooms, issue.location); if (room) room.resolved += 1; });
  lostFound.filter((item) => !['returned', 'closed'].includes(item.status)).forEach((item) => { const room = resolveRoom(rooms, item.location); if (room) { room.lost += 1; if (item.createdAt) room.lastActivity = String(item.createdAt).slice(0, 10); } });

  return rooms.map((room) => ({ ...room, health: Math.max(28, Math.min(100, room.health)), status: statusFor(room.health), eta: room.active ? room.health < 60 ? '45 minutes' : room.health < 75 ? '2 hours' : 'Today' : 'No action needed' }));
}

const RW = 3.6;
const RD = 2.9;
const WH = 2.0;

function Person({ position, rotation = 0, shirt = SHIRTS[0], seated = false }) {
  return <group position={position} rotation={[0, rotation, 0]}>
    {seated ? (
      <>
        <mesh position={[0, .5, -.13]}><boxGeometry args={[.26, .46, .2]} /><meshStandardMaterial color={shirt} /></mesh>
        <mesh position={[0, .92, -.13]}><sphereGeometry args={[.115, 10, 10]} /><meshStandardMaterial color="#e8c39a" /></mesh>
        <mesh position={[0, .34, .15]}><boxGeometry args={[.2, .14, .32]} /><meshStandardMaterial color="#43546b" /></mesh>
        <mesh position={[.12, .56, -.24]}><boxGeometry args={[.06, .28, .07]} /><meshStandardMaterial color="#e8c39a" /></mesh>
        <mesh position={[-.12, .56, -.24]}><boxGeometry args={[.06, .28, .07]} /><meshStandardMaterial color="#e8c39a" /></mesh>
      </>
    ) : (
      <>
        <mesh position={[-.07, .24, 0]}><boxGeometry args={[.07, .3, .09]} /><meshStandardMaterial color="#43546b" /></mesh>
        <mesh position={[.07, .24, 0]}><boxGeometry args={[.07, .3, .09]} /><meshStandardMaterial color="#43546b" /></mesh>
        <mesh position={[0, .6, 0]}><boxGeometry args={[.3, .44, .2]} /><meshStandardMaterial color={shirt} /></mesh>
        <mesh position={[.16, .66, 0]}><boxGeometry args={[.055, .34, .07]} /><meshStandardMaterial color="#e8c39a" /></mesh>
        <mesh position={[-.16, .66, 0]}><boxGeometry args={[.055, .34, .07]} /><meshStandardMaterial color="#e8c39a" /></mesh>
        <mesh position={[0, 1.02, 0]}><sphereGeometry args={[.13, 10, 10]} /><meshStandardMaterial color="#e8c39a" /></mesh>
        <mesh position={[0, 1.02, .1]}><sphereGeometry args={[.015, 6, 6]} /><meshStandardMaterial color="#2c2018" /></mesh>
      </>
    )}
  </group>;
}

function IssueMarker({ position, onClick }) {
  const ref = useRef();
  useFrame(({ clock }) => { if (ref.current) ref.current.material.emissiveIntensity = .5 + Math.sin(clock.elapsedTime * 3) * .3; });
  return <mesh ref={ref} position={position} onClick={(event) => { event.stopPropagation(); onClick(); }}>
    <sphereGeometry args={[.09, 12, 12]} />
    <meshStandardMaterial color="#d9504f" emissive="#d9504f" emissiveIntensity={.7} />
  </mesh>;
}

function CeilingFan({ position }) {
  const blades = useRef();
  useFrame((_, delta) => { if (blades.current) blades.current.rotation.y += delta * 7; });
  return <group position={position}>
    <mesh position={[0, .05, 0]}><cylinderGeometry args={[.04, .04, .26, 8]} /><meshStandardMaterial color="#c9d3ce" /></mesh>
    <group ref={blades} position={[0, -.01, 0]}>
      {[0, Math.PI / 2, Math.PI, Math.PI * 1.5].map((r) => <mesh key={r} rotation={[0, r, 0]}><boxGeometry args={[.85, .02, .13]} /><meshStandardMaterial color="#aabdb3" /></mesh>)}
    </group>
  </group>;
}

function Blackboard({ position, width = 1.9 }) {
  return <group position={position}>
    <mesh><boxGeometry args={[width, .82, .05]} /><meshStandardMaterial color="#27403a" /></mesh>
    <mesh position={[0, -.46, .01]}><boxGeometry args={[width, .035, .08]} /><meshStandardMaterial color="#9a6a3c" /></mesh>
    <mesh position={[0, .44, .01]}><boxGeometry args={[width, .035, .08]} /><meshStandardMaterial color="#d9e8e2" /></mesh>
  </group>;
}

function BenchRow({ position, rotation = 0, people = 3 }) {
  const seats = [];
  for (let i = 0; i < people; i++) seats.push(<Person key={i} position={[-.6 + i * .6, 0, -.04]} shirt={SHIRTS[(i + 1) % SHIRTS.length]} seated />);
  return <group position={position} rotation={[0, rotation, 0]}>
    <mesh position={[0, .48, 0]}><boxGeometry args={[1.9, .06, .56]} /><meshStandardMaterial color="#b6895a" /></mesh>
    <mesh position={[0, .24, -.2]}><boxGeometry args={[1.9, .44, .13]} /><meshStandardMaterial color="#8a5a33" /></mesh>
    <mesh position={[0, .44, .2]}><boxGeometry args={[1.9, .08, .18]} /><meshStandardMaterial color="#a47042" /></mesh>
    {seats}
  </group>;
}

function ChairRow({ position, count = 5 }) {
  return <group position={position}>
    {Array.from({ length: count }).map((_, i) => <mesh key={i} position={[-1.35 + i * .68, .5, 0]}><boxGeometry args={[.5, .08, .45]} /><meshStandardMaterial color="#a47042" /></mesh>)}
  </group>;
}

function ComputerStation({ position }) {
  return <group position={position}>
    <mesh position={[0, .42, 0]}><boxGeometry args={[.78, .44, .6]} /><meshStandardMaterial color="#b6895a" /></mesh>
    <mesh position={[0, .72, -.08]}><boxGeometry args={[.5, .34, .04]} /><meshStandardMaterial color="#2c3a4a" /></mesh>
    <mesh position={[0, .82, .08]}><boxGeometry args={[.28, .05, .18]} /><meshStandardMaterial color="#5a6b7d" /></mesh>
    <mesh position={[0, .16, -.36]}><boxGeometry args={[.42, .32, .4]} /><meshStandardMaterial color="#7c6a8c" /></mesh>
    <Person position={[0, 0, -.36]} shirt={SHIRTS[2]} seated />
  </group>;
}

function BookShelf({ position, rotation = 0 }) {
  const rows = [];
  for (let r = 0; r < 4; r++) for (let c = 0; c < 6; c++) rows.push(<mesh key={`${r}-${c}`} position={[-.75 + c * .3, .42 + r * .3, 0]}><boxGeometry args={[.24, .24, .12]} /><meshStandardMaterial color={['#3d7a8f', '#a0503c', '#5d5a86', '#8a6b3d', '#2f6d58', '#9a6a3c'][(r + c) % 6]} /></mesh>);
  return <group position={position} rotation={[0, rotation, 0]}>
    <mesh position={[0, .72, 0]}><boxGeometry args={[2.0, 1.5, .34]} /><meshStandardMaterial color="#9a7b52" /></mesh>
    {rows}
  </group>;
}

function ReadingTable({ position, people = 2 }) {
  const seated = [];
  for (let i = 0; i < people; i++) seated.push(<Person key={i} position={[-.35 + i * .7, 0, .5]} shirt={SHIRTS[(i + 2) % SHIRTS.length]} seated />);
  return <group position={position}>
    <mesh position={[0, .48, 0]}><boxGeometry args={[1.3, .05, .75]} /><meshStandardMaterial color="#c9a06c" /></mesh>
    <mesh position={[0, .24, 0]}><boxGeometry args={[1.22, .44, .67]} /><meshStandardMaterial color="#a5794a" /></mesh>
    {seated}
  </group>;
}

function OfficeDesk({ position }) {
  return <group position={position}>
    <mesh position={[0, .4, 0]}><boxGeometry args={[1.0, .4, .55]} /><meshStandardMaterial color="#a5794a" /></mesh>
    <mesh position={[0, .72, 0]}><boxGeometry args={[1.0, .05, .55]} /><meshStandardMaterial color="#8a6b3d" /></mesh>
    <mesh position={[0, .55, -.34]}><boxGeometry args={[.16, .06, .16]} /><meshStandardMaterial color="#2c3a4a" /></mesh>
    <mesh position={[-.42, .16, 0]}><boxGeometry args={[.14, .32, .3]} /><meshStandardMaterial color="#5a6b7d" /></mesh>
    <Person position={[0, 0, -.32]} shirt={SHIRTS[4]} seated />
  </group>;
}

function ToiletStall({ position }) {
  return <group position={position}>
    <mesh position={[0, .62, 0]}><boxGeometry args={[.6, 1.1, .56]} /><meshStandardMaterial color="#dfe9e4" /></mesh>
    <mesh position={[0, .46, -.1]}><boxGeometry args={[.4, .22, .3]} /><meshStandardMaterial color="#b7c6be" /></mesh>
    <mesh position={[0, .62, -.12]}><boxGeometry args={[.22, .3, .14]} /><meshStandardMaterial color="#9db2a7" /></mesh>
    <mesh position={[0, .62, -.08]}><boxGeometry args={[.3, .34, .06]} /><meshStandardMaterial color="#dfe9e4" /></mesh>
  </group>;
}

function Sink({ position }) {
  return <group position={position}>
    <mesh position={[0, .6, 0]}><boxGeometry args={[.5, .34, .4]} /><meshStandardMaterial color="#eef3f0" /></mesh>
    <mesh position={[0, .8, .05]}><boxGeometry args={[.42, .1, .04]} /><meshStandardMaterial color="#c4d6cc" /></mesh>
    <mesh position={[0, .95, .02]}><boxGeometry args={[.44, .34, .04]} /><meshStandardMaterial color="#aac9bb" /></mesh>
  </group>;
}

function WallLight({ position, length = .9, onIssue }) {
  return <group position={position}>
    <mesh><boxGeometry args={[length, .09, .05]} /><meshStandardMaterial color="#f3f7f5" emissive="#fff6d8" emissiveIntensity={.9} /></mesh>
    {onIssue && <IssueMarker position={[0, .1, .02]} onClick={onIssue} />}
  </group>;
}

function Window({ position, rotation = 0, width = 1.0 }) {
  return <group position={position} rotation={[0, rotation, 0]}>
    <mesh><boxGeometry args={[width, .7, .05]} /><meshStandardMaterial color="#bfe3f7" transparent opacity={.55} emissive="#bfe3f7" emissiveIntensity={.15} /></mesh>
    <mesh position={[0, .28, .01]}><boxGeometry args={[width, .05, .07]} /><meshStandardMaterial color="#8a9c93" /></mesh>
  </group>;
}

function ServerRack({ position }) {
  const rows = [];
  for (let r = 0; r < 4; r++) rows.push(<mesh key={r} position={[0, .35 + r * .3, 0]}><boxGeometry args={[.55, .24, .5]} /><meshStandardMaterial color="#2c3a4a" /></mesh>);
  return <group position={position}>{rows}</group>;
}

function LoungeSeat({ position, rotation = 0 }) {
  return <group position={position} rotation={[0, rotation, 0]}>
    <mesh position={[0, .4, 0]}><boxGeometry args={[1.5, .42, .6]} /><meshStandardMaterial color="#2f6d58" /></mesh>
    <mesh position={[0, .66, 0]}><boxGeometry args={[1.5, .12, .6]} /><meshStandardMaterial color="#3f8a6f" /></mesh>
    <Person position={[-.35, 0, 0]} shirt={SHIRTS[1]} seated />
    <Person position={[.35, 0, 0]} shirt={SHIRTS[3]} seated />
  </group>;
}

function Plant({ position }) {
  return <group position={position}>
    <mesh position={[0, .3, 0]}><cylinderGeometry args={[.14, .2, .6, 8]} /><meshStandardMaterial color="#8a5a33" /></mesh>
    <mesh position={[0, .7, 0]}><sphereGeometry args={[.34, 8, 8]} /><meshStandardMaterial color="#3f8a5f" /></mesh>
  </group>;
}

function ReceptionCounter({ position }) {
  return <group position={position}>
    <mesh position={[0, .5, 0]}><boxGeometry args={[1.4, 1.0, .5]} /><meshStandardMaterial color="#9a7b52" /></mesh>
    <mesh position={[0, .78, .3]}><boxGeometry args={[1.4, .05, .1]} /><meshStandardMaterial color="#5a6b7d" /></mesh>
    <Person position={[.3, 0, -.4]} shirt={SHIRTS[5]} />
    <Person position={[-.3, 0, .5]} shirt={SHIRTS[0]} />
  </group>;
}

function FoyerDecor({ position }) {
  return <group position={position}>
    <mesh position={[-1.1, .8, 0]}><cylinderGeometry args={[.1, .12, 1.6, 10]} /><meshStandardMaterial color="#d9e2dd" /></mesh>
    <mesh position={[1.1, .8, 0]}><cylinderGeometry args={[.1, .12, 1.6, 10]} /><meshStandardMaterial color="#d9e2dd" /></mesh>
    <Plant position={[0, 0, -.5]} />
  </group>;
}

function RoomInterior({ room, detailed }) {
  const type = room.type;
  if (type === 'classroom') return <>
    <Blackboard position={[0, 1.05, -1.18]} width={1.9} />
    <WallLight position={[-.6, 1.72, -1.32]} length={.5} /><WallLight position={[.6, 1.72, -1.32]} length={.5} />
    <Window position={[-1.66, 1.15, -.2]} rotation={Math.PI / 2} width={.9} />
    <BenchRow position={[-.88, 0, .05]} people={3} />
    <BenchRow position={[.4, 0, .05]} people={3} />
    <BenchRow position={[-.88, 0, .72]} people={3} />
    <BenchRow position={[.4, 0, .72]} people={3} />
    {detailed && <><CeilingFan position={[-.5, WH, -.4]} /><CeilingFan position={[.5, WH, .6]} /></>}
  </>;
  if (type === 'washroom') return <>
    {[-1.05, -0.35, .35, 1.05].map((x) => <ToiletStall key={x} position={[x, 0, -.55]} />)}
    {[-1.05, -0.35, .35, 1.05].slice(1).map((x) => <mesh key={x} position={[x - .35, .62, -.55]}><boxGeometry args={[.02, 1.1, .6]} /><meshStandardMaterial color="#c6d5cd" /></mesh>)}
    <Sink position={[-.55, 0, .95]} /><Sink position={[.55, 0, .95]} />
    <WallLight position={[0, 1.72, -1.28]} length={1.1} />
    <Person position={[-.2, 0, .3]} shirt={SHIRTS[1]} />
  </>;
  if (type === 'library & study') return <>
    <BookShelf position={[-1.35, 0, 0]} rotation={Math.PI / 2} /><BookShelf position={[1.35, 0, 0]} rotation={Math.PI / 2} />
    <ReadingTable position={[-.45, 0, .3]} people={2} /><ReadingTable position={[.55, 0, .9]} people={2} />
    {detailed && <CeilingFan position={[0, WH, -.3]} />}
  </>;
  if (type === 'seminar hall') return <>
    <Blackboard position={[0, 1.1, -1.18]} width={2.6} />
    <mesh position={[0, .5, -1.05]}><boxGeometry args={[2.8, .9, .4]} /><meshStandardMaterial color="#9a7b52" /></mesh>
    <ChairRow position={[0, 0, .1]} count={5} /><ChairRow position={[0, 0, .62]} count={5} /><ChairRow position={[0, 0, 1.05]} count={5} />
    <Person position={[0, 0, -1.15]} shirt={SHIRTS[2]} />
    {detailed && <CeilingFan position={[0, WH, .3]} />}
  </>;
  if (type === 'computer lab') return <>
    <ComputerStation position={[-1.05, 0, .15]} /><ComputerStation position={[-.15, 0, .15]} /><ComputerStation position={[.75, 0, .15]} />
    <ComputerStation position={[-1.05, 0, .85]} /><ComputerStation position={[-.15, 0, .85]} /><ComputerStation position={[.75, 0, .85]} />
    <WallLight position={[0, 1.72, -1.28]} length={1.4} />
    {detailed && <CeilingFan position={[0, WH, .3]} />}
  </>;
  if (type === 'office') return <>
    <OfficeDesk position={[-1.0, 0, .25]} /><OfficeDesk position={[0, 0, .25]} /><OfficeDesk position={[1.0, 0, .25]} />
    <mesh position={[-1.4, .8, -1.0]}><boxGeometry args={[.5, 1.5, .8]} /><meshStandardMaterial color="#8a9c93" /></mesh>
    {detailed && <CeilingFan position={[0, WH, -.3]} />}
  </>;
  if (type === 'server room') return <>
    <ServerRack position={[-.8, 0, -.4]} /><ServerRack position={[0, 0, -.4]} /><ServerRack position={[.8, 0, -.4]} />
    <Person position={[0, 0, .9]} shirt={SHIRTS[5]} />
  </>;
  if (type === 'medical room') return <>
    <mesh position={[-.8, .45, 0]}><boxGeometry args={[.6, .3, 1.6]} /><meshStandardMaterial color="#dfe9e4" /></mesh>
    <OfficeDesk position={[.8, 0, .1]} />
    <Person position={[-.8, 0, -.4]} shirt={SHIRTS[3]} seated />
  </>;
  if (type === 'foyer') return <>
    <ReceptionCounter position={[0, 0, -.6]} />
    <FoyerDecor position={[0, 0, .2]} />
    <LoungeSeat position={[-1.1, 0, .5]} rotation={Math.PI / 2} />
    <Person position={[1.1, 0, .2]} shirt={SHIRTS[0]} />
    <Person position={[1.1, 0, .7]} shirt={SHIRTS[4]} />
    {detailed && <CeilingFan position={[0, WH, .3]} />}
  </>;
  if (type === 'lounge') return <>
    <LoungeSeat position={[-1.1, 0, .3]} /><LoungeSeat position={[.1, 0, .3]} /><LoungeSeat position={[1.15, 0, .3]} />
    <Plant position={[-1.4, 0, -1.0]} /><Plant position={[1.4, 0, -1.0]} />
    {detailed && <CeilingFan position={[0, WH, -.2]} />}
  </>;
  if (type === 'security') return <>
    <OfficeDesk position={[0, 0, .2]} />
    <mesh position={[0, .75, -1.05]}><boxGeometry args={[.6, .8, .1]} /><meshStandardMaterial color="#2c3a4a" /></mesh>
  </>;
  if (type === 'circulation' || type === 'campus service') return <>
    <LoungeSeat position={[0, 0, .1]} />
  </>;
  return null;
}

function RoomShell({ room, y, selected, dimmed, detailed, showLabels, overlays, onSelect, onHover, onOpen3D }) {
  const wallColor = dimmed ? '#c9d3ce' : '#eef3f0';
  const door = room.z > 0 ? -1.42 : 1.42;
  return <group position={[room.x, y, room.z]}>
    <group onClick={(event) => { event.stopPropagation(); onSelect(room); }} onPointerOver={(event) => { event.stopPropagation(); document.body.style.cursor = 'pointer'; onHover(room); }} onPointerOut={() => { document.body.style.cursor = 'default'; onHover(null); }}>
      <mesh position={[0, 0.05, 0]} receiveShadow><boxGeometry args={[RW - .08, .08, RD - .08]} /><meshStandardMaterial color={dimmed ? '#dbe5e0' : '#dfe9e4'} transparent opacity={dimmed ? .2 : 1} /></mesh>
      <mesh position={[0, WH / 2, -RD / 2 + .05]}><boxGeometry args={[RW, WH, .08]} /><meshStandardMaterial color={wallColor} /></mesh>
      <mesh position={[-RW / 2 + .05, WH / 2, 0]}><boxGeometry args={[.08, WH, RD]} /><meshStandardMaterial color={wallColor} /></mesh>
      <mesh position={[RW / 2 - .05, WH / 2, 0]}><boxGeometry args={[.08, WH, RD]} /><meshStandardMaterial color={wallColor} /></mesh>
      <mesh position={[0, .5, door]}><boxGeometry args={[.72, 1.0, .06]} /><meshStandardMaterial color="#9a7b52" /></mesh>
      <mesh position={[0, .06, door - .02]} transparent opacity={0} depthWrite={false}><boxGeometry args={[RW - .2, WH - .1, .02]} /><meshStandardMaterial transparent opacity={0} /></mesh>
    </group>
    {!dimmed && <group position={[0, 0, 0]}><RoomInterior room={room} detailed={detailed} />{room.active > 0 && Array.from({ length: Math.min(room.active, 3) }).map((_, i) => <IssueMarker key={i} position={[-1.1 + i * 1.1, 1.2, -0.85]} onClick={() => onSelect(room)} />)}</group>}
    {showLabels && !dimmed && <Html position={[0, 1.75, 0]} center distanceFactor={13} zIndexRange={[20, 0]}><button className={`twin-room-label ${selected ? 'selected' : ''}`} onClick={() => onSelect(room)}><b>{room.code}</b><span>{room.name}</span>{room.active > 0 && <em>{room.active}</em>}</button></Html>}
    {room.type === 'classroom' && showLabels && !dimmed && <Html position={[0, 2.15, 0]} center distanceFactor={13}><button className="twin-3d-badge" title="Open 3D classroom model" onClick={(event) => { event.stopPropagation(); onOpen3D?.(room); }}><Box /> 3D</button></Html>}
    {overlays.lostFound && room.lost > 0 && !dimmed && <Html position={[1.15, 1.6, .6]} center distanceFactor={12}><button className="twin-scene-marker lost" title={`${room.lost} lost-and-found activities`} onClick={() => onSelect(room)}><PackageSearch />{room.lost}</button></Html>}
    {overlays.maintenance && room.maintenance && !dimmed && <Html position={[-1.1, 1.58, -.55]} center distanceFactor={12}><button className="twin-scene-marker maintenance" title="Maintenance in progress" onClick={() => onSelect(room)}><Wrench /></button></Html>}
  </group>;
}

function FloorArchitecture({ floor, rooms, floorIndex, exploded, selectedFloor, filters, selected, hovered, overlays, onSelect, onHover, onOpen3D }) {
  if (selectedFloor !== 'all' && Number(selectedFloor) !== floor.number) return null;
  const isolated = selectedFloor !== 'all';
  const y = isolated ? 0 : floorIndex * (exploded ? 3.85 : 2.45);
  return <group>
    <mesh position={[0, y - .82, 0]} receiveShadow><boxGeometry args={[21.7, .22, 9.5]} /><meshStandardMaterial color="#dbe7e1" roughness={.92} /><Edges color="#92aa9f" opacity={.35} transparent /></mesh>
    <mesh position={[0, y - .59, 0]}><boxGeometry args={[20.6, .05, 2.1]} /><meshStandardMaterial color="#e4dcc9" /></mesh>
    <mesh position={[0, y - .66, 0]} receiveShadow><boxGeometry args={[20.7, .08, 1.35]} /><meshStandardMaterial color="#f5f1e9" /></mesh>
    {[-10.45, 10.45].map((x) => <mesh key={x} position={[x, y, 0]}><boxGeometry args={[.14, 2.0, 9.2]} /><meshStandardMaterial color="#9bb1a7" transparent opacity={.5} /></mesh>)}
    <group position={[-9.65, y - .55, 0]}>{[0, 1, 2, 3, 4, 5].map((step) => <group key={step} position={[step * .26, step * .16, 0]}><mesh><boxGeometry args={[.55, .1, 1.05]} /><meshStandardMaterial color="#b6c8c0" /></mesh><mesh position={[0, -.07, -.48]}><boxGeometry args={[.55, .08, .08]} /><meshStandardMaterial color="#93a89e" /></mesh></group>)}</group>
    <mesh position={[9.35, y, 0]}><boxGeometry args={[.9, 1.9, 1.2]} /><meshStandardMaterial color="#8fa9a0" transparent opacity={.42} /><Edges color="#4d7164" /></mesh>
    {rooms.map((room) => {
      const textMatch = !filters.query || `${room.name} ${room.code} ${room.type} ${room.category}`.toLowerCase().includes(filters.query.toLowerCase());
      const typeMatch = filters.type === 'all' || room.type === filters.type;
      const severityMatch = filters.severity === 'all' || room.status === filters.severity;
      const categoryMatch = filters.category === 'all' || room.category.toLowerCase().includes(filters.category.toLowerCase());
      const departmentMatch = filters.department === 'all' || room.department === filters.department;
      const activityMatch = filters.activity === 'all' || (filters.activity === 'active' && room.active > 0) || (filters.activity === 'resolved' && room.resolved > 0 && room.active === 0) || (filters.activity === 'lost' && room.lost > 0);
      const dateMatch = (!filters.dateFrom || room.lastActivity >= filters.dateFrom) && (!filters.dateTo || room.lastActivity <= filters.dateTo);
      const dimmed = !(textMatch && typeMatch && severityMatch && categoryMatch && departmentMatch && activityMatch && dateMatch);
      const detailed = isolated || selected?.id === room.id || hovered?.id === room.id;
      return <RoomShell key={room.id} room={room} y={y} dimmed={dimmed} detailed={detailed} selected={selected?.id === room.id} showLabels={isolated || selected?.id === room.id || hovered?.id === room.id} overlays={overlays} onSelect={onSelect} onHover={onHover} onOpen3D={onOpen3D} />;
    })}
    <Html position={[-11.25, y, 0]} center distanceFactor={13}><button className="twin-floor-tag" onClick={() => filters.setFloor(String(floor.number))}><b>F{floor.number}</b><span>{floor.name}</span></button></Html>
  </group>;
}

function CampusBuilding({ rooms, selectedFloor, exploded, filters, selected, hovered, overlays, onSelect, onHover, onOpen3D }) {
  return <group position={[0, selectedFloor === 'all' ? -5.2 : .6, 0]} rotation={[0, -.08, 0]}>
    <mesh position={[0, -.6, 0]}><boxGeometry args={[22.4, .5, 10.1]} /><meshStandardMaterial color="#9db1a7" /></mesh>
    <mesh position={[0, -.57, 0]}><boxGeometry args={[22.6, .07, 10.3]} /><meshStandardMaterial color="#c9d6cf" /></mesh>
    {FLOOR_BLUEPRINTS.map((floor, index) => <FloorArchitecture key={floor.number} floor={floor} rooms={rooms.filter((room) => room.floor === floor.number)} floorIndex={index} exploded={exploded} selectedFloor={selectedFloor} filters={filters} selected={selected} hovered={hovered} overlays={overlays} onSelect={onSelect} onHover={onHover} onOpen3D={onOpen3D} />)}
  </group>;
}

function DigitalTwinScene({ rooms, selectedFloor, exploded, filters, selected, hovered, overlays, onSelect, onHover, onOpen3D, controlsRef }) {
  return <Canvas shadows dpr={[1, 1.5]} camera={{ position: [19, 15, 24], fov: 38, near: .1, far: 140 }} gl={{ antialias: true, alpha: false, preserveDrawingBuffer: true }} onPointerMissed={() => onSelect(null)}>
    <color attach="background" args={['#e9f1ed']} />
    <fog attach="fog" args={['#e9f1ed', 42, 90]} />
    <ambientLight intensity={1.1} />
    <hemisphereLight args={['#f7fffb', '#587267', 1.1]} />
    <directionalLight position={[12, 22, 9]} intensity={2.3} castShadow shadow-mapSize={[1024, 1024]} shadow-camera-far={70} />
    <CampusBuilding rooms={rooms} selectedFloor={selectedFloor} exploded={exploded} filters={filters} selected={selected} hovered={hovered} overlays={overlays} onSelect={onSelect} onHover={onHover} onOpen3D={onOpen3D} />
    <gridHelper args={[54, 36, '#abc0b6', '#cedbd5']} position={[0, -6.05, 0]} />
    <ContactShadows position={[0, -6, 0]} opacity={.34} scale={48} blur={2.5} far={20} />
    <OrbitControls ref={controlsRef} makeDefault enableDamping dampingFactor={.08} minDistance={3.2} maxDistance={48} maxPolarAngle={Math.PI / 2.04} target={[0, 1.7, 0]} />
  </Canvas>;
}

function Toggle({ checked, onChange, label, tone }) {
  return <label className="twin-toggle"><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><span className={tone || ''} /><b>{label}</b></label>;
}

function RoomDetails({ room, onClose, dark, issues = [], onOpen3D }) {
  const [asset, setAsset] = useState('');
  useEffect(() => { setAsset(''); }, [room?.id]);
  if (!room) return <div className="twin-detail-empty"><span><Building2 /></span><h3>Select a room</h3><p>Click any room to inspect its health, facilities, people, and service history.</p><div><span>Tip</span> Drag to rotate · scroll to zoom · double-click a floor to isolate</div></div>;
  const reportAsset = () => {
    const ref = campusRoomRef(room);
    const params = new URLSearchParams({ buildingId: ref.buildingId, buildingName: ref.buildingName, floor: ref.floor, floorName: ref.floorName, roomId: ref.roomId, roomName: ref.roomName, spaceType: ref.spaceType, assetName: asset });
    window.location.assign(`/app/report?${params.toString()}`);
  };
  return <div className={`twin-room-details ${dark ? 'on-dark' : ''}`}>
    <header><div><span>FLOOR {room.floor} · {room.code}</span><h2>{room.name}</h2><p>{room.type}</p></div><button onClick={onClose} aria-label="Close room details"><X /></button></header>
    <div className={`twin-health ${room.status}`}><div><span>ROOM HEALTH</span><strong>{room.health}</strong><small>/100</small></div><p><b>{room.status}</b><span>{room.active ? `${room.active} active issue${room.active === 1 ? '' : 's'}` : 'Operating normally'}</span></p></div>
    <div className="twin-detail-stats"><div><strong>{room.active}</strong><span>Active</span></div><div><strong>{room.resolved}</strong><span>Resolved</span></div><div><strong>{room.recurring}</strong><span>Recurring</span></div><div><strong>{room.lost}</strong><span>L&F activity</span></div></div>
    {issues.length > 0 && <section className="twin-room-issues"><span>ISSUES IN THIS ROOM · {issues.length}</span>{issues.map((issue) => <article key={issue.id}><i className={`priority ${issue.priority}`} /><div><b>{issue.title}</b><small>{issue.id} · {issue.status.replace('_', ' ')}{issue.assetName ? ` · ${issue.assetName}` : ''}</small></div></article>)}</section>}
    {room.type === 'classroom' && onOpen3D && <button className="twin-open3d" onClick={onOpen3D}><Box /> Open 3D classroom model</button>}
    <section className="twin-asset-report"><span>REPORT AN ISSUE IN THIS ROOM</span><select value={asset} onChange={(event) => setAsset(event.target.value)}><option value="">Choose an asset / fixture…</option>{(SPACE_ASSETS[room.type] || SPACE_ASSETS['campus service']).map((item) => <option key={item} value={item}>{item}</option>)}</select>{asset && <button onClick={reportAsset}><Wrench /> Report issue — {asset}</button>}</section>
    <dl className="twin-facts"><div><dt><Activity /> Current signal</dt><dd>{room.category}</dd></div><div><dt><Building2 /> Assigned team</dt><dd>{room.department}</dd></div><div><dt><MapPin /> Location</dt><dd>Floor {room.floor} · {room.floorName}</dd></div><div><dt><Clock3 /> Estimated resolution</dt><dd>{room.eta}</dd></div><div><dt><Wrench /> Last maintenance</dt><dd>{room.lastMaintenance}</dd></div><div><dt><Maximize2 /> Capacity</dt><dd>{room.capacity} people</dd></div></dl>
    <section className="twin-facilities"><span>FACILITIES</span><div>{room.facilities.map((facility) => <em key={facility}><Check /> {facility}</em>)}</div></section>
    {room.maintenance && <div className="twin-maintenance-note"><Wrench /><div><b>Maintenance in progress</b><span>Technician is currently assigned to this room.</span></div></div>}
  </div>;
}

export function DigitalTwin({ data }) {
  const rooms = useMemo(() => buildRooms(data?.issues, data?.lostFound), [data?.issues, data?.lostFound]);
  const roomIssues = useMemo(() => {
    const map = {}; rooms.forEach((room) => { map[room.id] = []; });
    (data?.issues || []).forEach((issue) => { const room = resolveRoom(rooms, issue.location); if (room) map[room.id].push(issue); });
    return map;
  }, [rooms, data?.issues]);
  const [selectedFloor, setSelectedFloor] = useState('all');
  const [selected, setSelected] = useState(() => rooms.find((room) => room.name === 'Classroom 202'));
  const [hovered, setHovered] = useState(null);
  const [exploded, setExploded] = useState(true);
  const [filters, setFilters] = useState({ query: '', type: 'all', severity: 'all', category: 'all', department: 'all', activity: 'all', dateFrom: '', dateTo: '' });
  const [overlays, setOverlays] = useState({ issues: true, lostFound: true, maintenance: true });
  const [playing, setPlaying] = useState(false);
  const [replayStep, setReplayStep] = useState(TIMELINE.length);
  const [fullscreen, setFullscreen] = useState(false);
  const [sketchfabRoom, setSketchfabRoom] = useState(null);
  const controlsRef = useRef();
  const pageRef = useRef();

  useEffect(() => {
    if (!playing) return undefined;
    if (replayStep >= TIMELINE.length) { setPlaying(false); return undefined; }
    const timer = setTimeout(() => setReplayStep((value) => value + 1), 1050);
    return () => clearTimeout(timer);
  }, [playing, replayStep]);

  useEffect(() => {
    const onFsChange = () => setFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, []);

  useEffect(() => {
    if (selectedFloor === 'all' || selected?.floor === Number(selectedFloor)) return;
    const floorRooms = rooms.filter((room) => room.floor === Number(selectedFloor));
    setSelected(floorRooms.sort((a, b) => a.health - b.health)[0] || null);
  }, [selectedFloor, rooms, selected?.floor]);

  const toggleFullscreen = () => {
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    else pageRef.current?.requestFullscreen?.().catch(() => {});
  };
  const startReplay = () => { if (playing) { setPlaying(false); return; } setReplayStep(0); setPlaying(true); };
  const open3D = (room) => setSketchfabRoom(room);
  const activeRooms = rooms.filter((room) => room.active > 0).length;
  const criticalRooms = rooms.filter((room) => room.status === 'critical').length;
  const averageHealth = Math.round(rooms.reduce((sum, room) => sum + room.health, 0) / rooms.length);
  const typeOptions = [...new Set(rooms.map((room) => room.type))];
  const departmentOptions = [...new Set(rooms.map((room) => room.department))].sort();
  const categoryOptions = ['Electrical', 'Network', 'Furniture', 'Safety', 'Plumbing', 'Hardware', 'Lighting', 'General maintenance'];
  const sceneFilters = { ...filters, setFloor: setSelectedFloor };

  return <div ref={pageRef} className={`digital-twin-page ${fullscreen ? 'fullscreen' : ''}`}>
    <header className="twin-page-head"><div><span className="kicker">LIVE SPATIAL OPERATIONS</span><h1>Campus Digital Twin</h1><p>Explore the five-floor Academic Block A — classrooms, computer labs, seminar hall, library, offices and washrooms, with live people and service hotspots.</p></div><div><span className="twin-live-dot" /><b>Digital twin online</b><small>50 spatial nodes connected</small></div></header>
    <section className="twin-command-bar">
      <div className="twin-search"><Search /><input value={filters.query} onChange={(event) => setFilters({ ...filters, query: event.target.value })} placeholder="Search room, facility, or issue…" />{filters.query && <button onClick={() => setFilters({ ...filters, query: '' })}><X /></button>}</div>
      <div className="twin-command-actions"><button className={exploded ? 'active' : ''} onClick={() => setExploded(!exploded)}><Layers3 /> {exploded ? 'Exploded view' : 'Stack floors'}</button><button onClick={() => controlsRef.current?.reset()}><RotateCcw /> Reset view</button><button className={playing ? 'replaying' : ''} onClick={startReplay}>{playing ? <Pause /> : <Play />} {playing ? 'Pause replay' : 'Replay history'}</button></div>
    </section>

    <section className="twin-summary">
      <article><span className="good"><Activity /></span><div><small>CAMPUS HEALTH</small><strong>{averageHealth}%</strong></div></article>
      <article><span className="orange"><AlertTriangle /></span><div><small>ROOMS WITH ISSUES</small><strong>{activeRooms}</strong></div></article>
      <article><span className="red"><Wrench /></span><div><small>CRITICAL SPACES</small><strong>{criticalRooms}</strong></div></article>
      <article><span className="blue"><PackageSearch /></span><div><small>LOST & FOUND SIGNALS</small><strong>{rooms.reduce((sum, room) => sum + room.lost, 0)}</strong></div></article>
    </section>

    <section className="twin-workspace">
      <aside className="twin-control-panel">
        <div className="twin-panel-heading"><div><span><Box /></span><div><b>Academic Block A</b><small>5 floors · {rooms.length} rooms</small></div></div><ChevronRight /></div>
        <section><h3>Floor navigator</h3><div className="twin-floor-list"><button className={selectedFloor === 'all' ? 'active' : ''} onClick={() => setSelectedFloor('all')}><span>ALL</span><div><b>Whole building</b><small>Live overview</small></div></button>{FLOOR_BLUEPRINTS.slice().reverse().map((floor) => <button className={selectedFloor === String(floor.number) ? 'active' : ''} onClick={() => setSelectedFloor(String(floor.number))} key={floor.number}><span>{floor.number}</span><div><b>{floor.name}</b><small>{rooms.filter((room) => room.floor === floor.number && room.active).length} rooms need attention</small></div></button>)}</div></section>
        <section><h3><Filter /> Filters</h3><label className="twin-field">Room type<select value={filters.type} onChange={(event) => setFilters({ ...filters, type: event.target.value })}><option value="all">All room types</option>{typeOptions.map((type) => <option key={type} value={type}>{type}</option>)}</select></label><label className="twin-field">Complaint type<select value={filters.category} onChange={(event) => setFilters({ ...filters, category: event.target.value })}><option value="all">All complaint types</option>{categoryOptions.map((category) => <option key={category} value={category}>{category}</option>)}</select></label><label className="twin-field">Health status<select value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value })}><option value="all">All health levels</option><option value="healthy">Healthy</option><option value="watch">Watch</option><option value="attention">Needs attention</option><option value="critical">Critical</option></select></label><label className="twin-field">Department<select value={filters.department} onChange={(event) => setFilters({ ...filters, department: event.target.value })}><option value="all">All departments</option>{departmentOptions.map((department) => <option key={department} value={department}>{department}</option>)}</select></label><label className="twin-field">Activity status<select value={filters.activity} onChange={(event) => setFilters({ ...filters, activity: event.target.value })}><option value="all">Resolved & unresolved</option><option value="active">Unresolved only</option><option value="resolved">Resolved only</option><option value="lost">Lost & found activity</option></select></label><div className="twin-date-fields"><label className="twin-field">From<input type="date" value={filters.dateFrom} onChange={(event) => setFilters({ ...filters, dateFrom: event.target.value })} /></label><label className="twin-field">To<input type="date" value={filters.dateTo} onChange={(event) => setFilters({ ...filters, dateTo: event.target.value })} /></label></div></section>
        <section><h3>Live layers</h3><Toggle checked={overlays.issues} onChange={(value) => setOverlays({ ...overlays, issues: value })} label="Complaint heatmap" tone="heat" /><Toggle checked={overlays.lostFound} onChange={(value) => setOverlays({ ...overlays, lostFound: value })} label="Lost & found" tone="lost" /><Toggle checked={overlays.maintenance} onChange={(value) => setOverlays({ ...overlays, maintenance: value })} label="Maintenance" tone="maintenance" /></section>
      </aside>

      <section className="twin-stage-card">
        <header><div><span className="twin-live-dot" /><div><b>Live spatial view</b><small>{selectedFloor === 'all' ? 'All floors visible' : `${FLOOR_BLUEPRINTS[Number(selectedFloor) - 1].name} isolated`}</small></div></div><span>UPDATED JUST NOW <button className="twin-fullscreen-btn" onClick={toggleFullscreen} title="Toggle full screen">{fullscreen ? <Minimize2 /> : <Maximize2 />}</button></span></header>
        <div className="twin-canvas-wrap"><DigitalTwinScene rooms={rooms} selectedFloor={selectedFloor} exploded={exploded} filters={sceneFilters} selected={selected} hovered={hovered} overlays={overlays} onSelect={setSelected} onHover={setHovered} onOpen3D={open3D} controlsRef={controlsRef} />
          <div className="twin-view-hint"><span>LEFT DRAG</span> Rotate <i /> <span>SCROLL</span> Zoom <i /> <span>RIGHT DRAG</span> Pan</div>
          <div className="twin-legend"><b>Room health</b>{Object.entries(STATUS_COLORS).slice(0, 4).map(([key, color]) => <span key={key}><i style={{ background: color }} />{key}</span>)}<span><i className="lost" />lost & found</span><span><i className="maintenance" />in progress</span></div>
          {hovered && <div className="twin-hover-card"><span>{hovered.code} · FLOOR {hovered.floor}</span><b>{hovered.name}</b><p><i style={{ background: STATUS_COLORS[hovered.status] }} /> {hovered.status} · {hovered.health}/100</p><small>{hovered.active} active complaints · {hovered.category}</small></div>}
        </div>
        <div className="twin-cluster-alert"><Sparkles /><div><b>Possible common root cause detected on Floor 3</b><span>Network and cooling reports are clustered across three nearby rooms.</span></div><button onClick={() => setSelectedFloor('3')}>Inspect floor <ChevronRight /></button></div>
      </section>

      <aside className="twin-insight-panel"><RoomDetails room={selected} onClose={() => setSelected(null)} issues={roomIssues[selected?.id] || []} onOpen3D={() => selected && open3D(selected)} /><section className="twin-timeline"><header><div><b>Live timeline</b><small>Operational replay</small></div><span>{replayStep}/{TIMELINE.length}</span></header><div>{TIMELINE.map((event, index) => <article className={index < replayStep ? 'visible' : ''} key={`${event.time}-${event.title}`}><span>{event.time}</span><i /><div><b>{event.title}</b><small>{event.detail}</small></div></article>)}</div></section></aside>
    </section>

    {fullscreen && <div className="twin-fullscreen-detail"><RoomDetails room={selected} dark onClose={() => setSelected(null)} issues={roomIssues[selected?.id] || []} onOpen3D={() => selected && open3D(selected)} /></div>}
    {sketchfabRoom && <div className="twin-sketchfab-overlay"><header><button onClick={() => setSketchfabRoom(null)}><X /> Back to building</button><span>{sketchfabRoom.name} · Floor {sketchfabRoom.floor}</span></header><iframe src={`https://sketchfab.com/3d-models/${SKETCHFAB_CLASSROOM}/embed?autostart=1&preload=1&ui_theme=dark`} allow="autoplay; fullscreen; xr-spatial-tracking" allowFullScreen title="Classroom 3D reference" /></div>}
  </div>;
}