const slug = (value) => String(value).toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

export const SPACE_ASSETS = {
  classroom: ['Bench / desk', 'Chair', 'Blackboard', 'Ceiling fan', 'Wall light', 'Projector', 'Smart board', 'Power outlet', 'Door / lock', 'Window', 'Other'],
  'seminar hall': ['Stage', 'Chair', 'Projector', 'PA system', 'Ceiling fan', 'Wall light', 'Air conditioner', 'Power outlet', 'Other'],
  washroom: ['Toilet', 'Wash basin', 'Tap', 'Flush system', 'Cubicle door', 'Mirror', 'Exhaust fan', 'Ceiling light', 'Hand dryer', 'Other'],
  library: ['Bookshelf', 'Reading desk', 'Chair', 'Computer kiosk', 'Ceiling light', 'Air conditioner', 'Power outlet', 'Other'],
  'computer lab': ['Computer', 'Monitor', 'Keyboard / mouse', 'Lab desk', 'Projector', 'Network point', 'Air conditioner', 'UPS', 'Ceiling light', 'Other'],
  laboratory: ['Lab bench', 'Equipment', 'Power outlet', 'Safety station', 'Sink / tap', 'Exhaust system', 'Projector', 'Ceiling light', 'Other'],
  office: ['Desk', 'Chair', 'Computer', 'Printer', 'Air conditioner', 'Ceiling light', 'Door / lock', 'Other'],
  'server room': ['Server rack', 'Network switch', 'UPS', 'Air conditioner', 'Fire sensor', 'Access control', 'Ceiling light', 'Other'],
  'medical room': ['Examination bed', 'Medicine cabinet', 'Wash basin', 'Air conditioner', 'Ceiling light', 'Other'],
  'lost & found': ['Storage shelf', 'Service counter', 'Computer', 'Door / lock', 'Ceiling light', 'Other'],
  security: ['CCTV camera', 'Monitor', 'Access control', 'Radio', 'Ceiling light', 'Other'],
  circulation: ['Lift', 'Lift button', 'Emergency light', 'Signage', 'Handrail', 'Other'],
  'campus service': ['Service counter', 'Furniture', 'Ceiling light', 'Power outlet', 'Door / lock', 'Other'],
  foyer: ['Seating bench', 'Reception counter', 'Display screen', 'Plant', 'Ceiling light', 'Power outlet', 'Other'],
  lounge: ['Sofa / bench', 'Table', 'Drinking water', 'Ceiling light', 'Power outlet', 'Other'],
};

export const inferSpaceType = (name) => {
  const value = String(name).toLowerCase();
  if (value.includes('seminar')) return 'seminar hall';
  if (value.includes('classroom')) return 'classroom';
  if (value.includes('washroom') || value.includes('toilet')) return 'washroom';
  if (value.includes('foyer')) return 'foyer';
  if (value.includes('lounge')) return 'lounge';
  if (value.includes('computer') || value.includes('digital library')) return 'computer lab';
  if (value.includes('lab')) return 'laboratory';
  if (value.includes('library') || value.includes('reading') || value.includes('archive')) return 'library';
  if (value.includes('server') || value.includes('network')) return 'server room';
  if (value.includes('medical')) return 'medical room';
  if (value.includes('office') || value.includes('cabin') || value.includes('staff') || value.includes('cell')) return 'office';
  if (value.includes('lost')) return 'lost & found';
  if (value.includes('security')) return 'security';
  if (value.includes('lift') || value.includes('lobby') || value.includes('stair')) return 'circulation';
  return 'campus service';
};

const createBuilding = ({ id, name, shortName, description, position, accent, floors }) => ({
  id, name, shortName, description, position, accent,
  floors: floors.map((floor, floorIndex) => ({
    number: floorIndex + 1,
    name: floor.name,
    rooms: floor.rooms.map((name, roomIndex) => {
      const type = inferSpaceType(name);
      return {
        id: `${id}-f${floorIndex + 1}-${slug(name)}`,
        code: name.match(/\d{3}/)?.[0] || `${shortName.slice(0, 1)}${floorIndex + 1}-${String(roomIndex + 1).padStart(2, '0')}`,
        name,
        type,
        assets: SPACE_ASSETS[type] || SPACE_ASSETS['campus service'],
      };
    }),
  })),
});

export const CAMPUS_BUILDINGS = [
  createBuilding({
    id: 'academic-block-a', name: 'Academic Block A', shortName: 'Academic', accent: '#db765d', position: [-7, 0, 1],
    description: 'Five-storey teaching block with a glazed central atrium and two concrete classroom wings.',
    floors: [
      { name: 'Ground & foyer', rooms: ['Foyer', 'Seating Lounge', 'Reception', 'Security Desk', 'Admin Office', 'Principal Cabin', 'Staff Office', 'Medical Room', 'Washroom (Male)', 'Washroom (Female)'] },
      { name: 'First floor', rooms: ['Office Suite', 'Seminar Hall', 'Library', 'Computer Lab', 'Classroom 201', 'Classroom 202', 'Classroom 203', 'Classroom 204', 'Washroom (Male)', 'Washroom (Female)'] },
      { name: 'Classrooms & labs', rooms: ['Classroom 301', 'Classroom 302', 'Classroom 303', 'Classroom 304', 'Computer Lab 2', 'Electronics Lab', 'Server / Network Room', 'Faculty Cabin', 'Washroom (Male)', 'Washroom (Female)'] },
      { name: 'Science & innovation', rooms: ['Classroom 401', 'Classroom 402', 'Classroom 403', 'Classroom 404', 'Electronics Lab', 'IoT / Robotics Lab', 'Innovation / Project Lab', 'Equipment Storage', 'Washroom (Male)', 'Washroom (Female)'] },
      { name: 'Library & study', rooms: ['Classroom 501', 'Classroom 502', 'Classroom 503', 'Classroom 504', 'Library', 'Reading Hall', 'Exam Cell', 'Discussion Room', 'Washroom (Male)', 'Washroom (Female)'] },
    ],
  }),
  createBuilding({
    id: 'central-library', name: 'Central Library', shortName: 'Library', accent: '#d7a947', position: [9, 0, -4],
    description: 'A transparent two-storey learning commons with visible bookshelves and reading terraces.',
    floors: [
      { name: 'Learning commons', rooms: ['Library Reception', 'Open Stacks', 'Reading Hall', 'Digital Library', 'Discussion Room', 'Washroom (Male)', 'Washroom (Female)'] },
      { name: 'Research collection', rooms: ['Reference Library', 'Journal Archive', 'Silent Reading Room', 'Computer Zone', 'Librarian Office', 'Washroom (Male)', 'Washroom (Female)'] },
    ],
  }),
  createBuilding({
    id: 'innovation-centre', name: 'Innovation Centre', shortName: 'Innovation', accent: '#4f91a8', position: [8, 0, 8],
    description: 'Three-storey technology hub with project studios, laboratories, and a glass collaboration spine.',
    floors: [
      { name: 'Makers & projects', rooms: ['Maker Lab', 'Project Studio', 'Seminar Room', 'Equipment Storage', 'Washroom (Male)', 'Washroom (Female)'] },
      { name: 'Computing labs', rooms: ['Computer Lab 1', 'Computer Lab 2', 'AI Lab', 'Server / Network Room', 'Faculty Cabin', 'Washroom (Male)', 'Washroom (Female)'] },
      { name: 'Research labs', rooms: ['Electronics Lab', 'IoT / Robotics Lab', 'Research Studio', 'Meeting Room', 'Staff Room', 'Washroom (Male)', 'Washroom (Female)'] },
    ],
  }),
];

export const getBuilding = (id) => CAMPUS_BUILDINGS.find((building) => building.id === id) || CAMPUS_BUILDINGS[0];

export const campusLocation = ({ buildingName, floor, floorName, roomName, assetName }) =>
  [buildingName, floor ? `Floor ${floor}${floorName ? ` - ${floorName}` : ''}` : '', roomName, assetName].filter(Boolean).join(' · ');

